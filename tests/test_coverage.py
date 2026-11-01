from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

from scripts import build as builder


class CoverageTests(unittest.TestCase):
    def check(self, source, candidates, behavior="domain"):
        coverage = builder.RuleCoverage(behavior, source)
        for candidate, expected in candidates.items():
            with self.subTest(source=source, candidate=candidate):
                self.assertEqual(coverage.covers(candidate, "classical"), expected)

    def test_exact_domain_does_not_cover_descendants_or_a_suffix(self):
        self.check(["example.org"], {
            "DOMAIN,example.org": True,
            "DOMAIN,EXAMPLE.ORG": True,
            "DOMAIN,child.example.org": False,
            "DOMAIN-SUFFIX,example.org": False,
        })

    def test_inclusive_suffix_covers_apex_descendants_and_narrower_suffixes(self):
        self.check(["+.example.org"], {
            "DOMAIN,example.org": True,
            "DOMAIN,a.b.example.org": True,
            "DOMAIN-SUFFIX,example.org": True,
            "DOMAIN-SUFFIX,child.example.org": True,
            "DOMAIN,otherexample.org": False,
            "DOMAIN,example.org.other": False,
            "DOMAIN-SUFFIX,org": False,
        })

    def test_descendant_suffix_excludes_apex(self):
        self.check([".example.org"], {
            "DOMAIN,example.org": False,
            "DOMAIN,a.example.org": True,
            "DOMAIN,a.b.example.org": True,
            "DOMAIN-SUFFIX,example.org": False,
            "DOMAIN-SUFFIX,a.example.org": True,
        })

    def test_wildcard_matches_only_one_label(self):
        self.check(["*.example.org"], {
            "DOMAIN,example.org": False,
            "DOMAIN,a.example.org": True,
            "DOMAIN,a.b.example.org": False,
            "DOMAIN-SUFFIX,example.org": False,
            "DOMAIN-SUFFIX,a.example.org": False,
        })

    def test_domain_patterns_have_distinct_coverage_boundaries(self):
        cases = {
            "+.example.org": {"+.example.org": True, ".example.org": True, "*.example.org": True},
            ".example.org": {"+.example.org": False, ".example.org": True, "*.example.org": True,
                             "+.a.example.org": True, "example.org": False},
            "*.example.org": {"+.example.org": False, ".example.org": False, "*.example.org": True,
                              "*.a.example.org": False, ".a.example.org": False,
                              "+.a.example.org": False, "a.example.org": True,
                              "a.b.example.org": False},
            "example.org": {"+.example.org": False, ".example.org": False, "*.example.org": False},
        }
        for source, candidates in cases.items():
            coverage = builder.RuleCoverage("domain", [source])
            for rule, expected in candidates.items():
                with self.subTest(source=source, rule=rule):
                    self.assertEqual(coverage.covers(rule, "domain"), expected)

    def test_classical_suffix_also_covers_domain_patterns(self):
        coverage = builder.RuleCoverage("classical", ["DOMAIN-SUFFIX,example.org"])
        for rule in ("example.org", "+.example.org", ".example.org", "*.example.org", "a.example.org"):
            with self.subTest(rule=rule):
                self.assertTrue(coverage.covers(rule, "domain"))
        self.assertFalse(coverage.covers("+.org", "domain"))

    def test_unknown_classical_rules_require_identical_classical_entries(self):
        rules = ["DOMAIN-KEYWORD,example", "DOMAIN-REGEX,.*example.*",
                 "PROCESS-NAME,example.exe", "DOMAIN-SUFFIX,.org",
                 "DOMAIN,*.example.org", "DOMAIN-SUFFIX,example.org,no-resolve"]
        broad = builder.RuleCoverage("domain", ["+.org", "*.example.org", ".org"])
        for rule in rules:
            with self.subTest(rule=rule):
                self.assertFalse(broad.covers(rule, "classical"))
                self.assertTrue(builder.RuleCoverage("classical", [rule]).covers(rule, "classical"))
        keywords = builder.RuleCoverage("classical", ["DOMAIN-KEYWORD,example"])
        self.assertFalse(keywords.covers("DOMAIN-KEYWORD,EXAMPLE", "classical"))
        self.assertFalse(keywords.covers("DOMAIN,example.org", "classical"))

    def test_unknown_patterns_are_not_interpreted_as_suffixes(self):
        coverage = builder.RuleCoverage("domain", ["*.*.example.org", "foo*.example.org", "+.example..org"])
        for rule in ("DOMAIN,a.b.example.org", "DOMAIN,foobar.example.org", "DOMAIN-SUFFIX,example.org"):
            with self.subTest(rule=rule):
                self.assertFalse(coverage.covers(rule, "classical"))
        coverage = builder.RuleCoverage("classical", ["DOMAIN-SUFFIX,.org", "DOMAIN-SUFFIX,*.example.org"])
        self.assertFalse(coverage.covers("DOMAIN,example.org", "classical"))
        self.assertFalse(coverage.covers("+.example.org", "domain"))

    def test_filter_preserves_order_and_attributes_each_removal_once(self):
        first = builder.RuleCoverage("domain", ["+.covered.example.org"])
        second = builder.RuleCoverage("classical", ["DOMAIN-SUFFIX,covered.example.org"])
        rules = ["DOMAIN,z.example.org", "DOMAIN,a.covered.example.org", "DOMAIN,a.example.org"]
        kept, counts = builder.remove_covered_rules(rules, "classical", {"first": first, "second": second})
        self.assertEqual(kept, [rules[0], rules[2]])
        self.assertEqual(counts, {"first": 1})
        self.assertEqual(rules, ["DOMAIN,z.example.org", "DOMAIN,a.covered.example.org", "DOMAIN,a.example.org"])


class DependencyTests(unittest.TestCase):
    def test_dependencies_are_ordered_before_dependents(self):
        groups = {"final": {"exclude_covered_by": ["middle"]},
                  "middle": {"exclude_covered_by": ["base"]}, "base": {}, "independent": {}}
        self.assertEqual(builder.ruleset_order(groups), ["base", "middle", "final", "independent"])
        self.assertEqual(list(groups), ["final", "middle", "base", "independent"])

    def test_invalid_dependency_lists_are_rejected(self):
        for dependencies in (None, "base", [None], [{}], ["unknown"], ["extra"], ["base", "base"]):
            with self.subTest(dependencies=dependencies):
                with self.assertRaises(builder.BuildError):
                    builder.ruleset_order({"base": {}, "extra": {"exclude_covered_by": dependencies}})

    def test_cycles_are_rejected_even_when_not_first(self):
        with self.assertRaisesRegex(builder.BuildError, "cycle"):
            builder.ruleset_order({"independent": {}, "a": {"exclude_covered_by": ["b"]},
                                   "b": {"exclude_covered_by": ["c"]}, "c": {"exclude_covered_by": ["a"]}})

    def test_manifest_loading_validates_coverage_dependencies(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.yaml"
            manifest = {"version": 1, "repository": "owner/rules", "sources": {
                "base": {"behavior": "classical", "format": "text", "path": "rules/base.list"}},
                "rulesets": {"base": {"behavior": "classical", "sources": ["base"],
                                      "exclude_covered_by": ["missing"]}}}
            path.write_text(yaml.safe_dump(manifest), encoding="utf-8")
            with self.assertRaisesRegex(builder.BuildError, "Unknown coverage dependency"):
                builder.load_manifest(path)


class BuildCoverageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "rules").mkdir()
        self.base = self.root / "rules/base.list"
        self.extra = self.root / "rules/extra.list"
        self.base.write_text("DOMAIN-SUFFIX,covered.example.org\n", encoding="utf-8")
        self.extra.write_text("DOMAIN,a.covered.example.org\nDOMAIN,a.covered.example.org\n"
                              "DOMAIN,other.example.org\n", encoding="utf-8")
        self.original_extra = self.extra.read_bytes()
        self.binary = self.root / "binary"
        self.binary.touch()
        self.output = self.root / "dist"
        self.manifest = {"version": 1, "repository": "owner/rules", "sources": {
            name: {"behavior": "classical", "format": "text", "path": f"rules/{name}.list"}
            for name in ("base", "extra")}, "rulesets": {
                "extra": {"behavior": "classical", "sources": ["extra"], "exclude_covered_by": ["base"]},
                "base": {"behavior": "classical", "sources": ["base"]}}}

    def run_build(self):
        with patch.object(builder, "run_mihomo", return_value="test"), \
                patch.object(builder, "validate_providers", return_value={}), redirect_stdout(io.StringIO()):
            return builder.build(self.manifest, self.binary, self.output, self.root / "cache",
                                 offline=True, source_root=self.root)

    def test_build_removes_coverage_separately_from_exact_duplicates(self):
        result = self.run_build()
        self.assertEqual(list(result["rulesets"]), ["base", "extra"])
        stats = result["rulesets"]["extra"]
        self.assertEqual(stats["input_rules"], 3)
        self.assertEqual(stats["unique_rules"], 2)
        self.assertEqual(stats["exact_duplicates_removed"], 1)
        self.assertEqual(stats["covered_rules_removed"], 1)
        self.assertEqual(stats["covered_by"], {"base": 1})
        self.assertEqual(stats["exclude_covered_by"], ["base"])
        self.assertEqual(stats["rules"], 1)
        self.assertEqual(builder.read_rules(self.output / "extra.list", "text"), ["DOMAIN,other.example.org"])
        self.assertEqual(self.extra.read_bytes(), self.original_extra)

    def test_rule_reappears_when_dependency_stops_covering_it(self):
        self.run_build()
        self.base.write_text("DOMAIN,new.example.org\n", encoding="utf-8")
        result = self.run_build()
        self.assertEqual(builder.read_rules(self.output / "extra.yaml", "yaml"),
                         ["DOMAIN,a.covered.example.org", "DOMAIN,other.example.org"])
        self.assertEqual(result["rulesets"]["extra"]["covered_rules_removed"], 0)
        self.assertEqual(result["rulesets"]["extra"]["exclude_covered_by"], ["base"])
        self.assertEqual(result["rulesets"]["extra"]["exact_duplicates_removed"], 1)
        self.assertEqual(self.extra.read_bytes(), self.original_extra)

    def test_full_coverage_fails_without_replacing_last_output_or_sources(self):
        self.run_build()
        previous_output = (self.output / "manifest.json").read_bytes()
        self.base.write_text("DOMAIN-SUFFIX,example.org\n", encoding="utf-8")
        with self.assertRaisesRegex(builder.BuildError, "Empty effective ruleset"):
            self.run_build()
        self.assertEqual((self.output / "manifest.json").read_bytes(), previous_output)
        self.assertEqual(self.extra.read_bytes(), self.original_extra)

    def test_coverage_uses_only_rules_still_emitted_by_dependency(self):
        self.manifest["rulesets"]["base"]["exclude_covered_by"] = ["primary"]
        self.manifest["rulesets"]["primary"] = {"behavior": "classical", "sources": ["primary"]}
        self.manifest["sources"]["primary"] = {"behavior": "classical", "format": "text",
                                               "path": "rules/primary.list"}
        (self.root / "rules/primary.list").write_text("DOMAIN-SUFFIX,covered.example.org\n", encoding="utf-8")
        self.base.write_text("DOMAIN-SUFFIX,covered.example.org\nDOMAIN,base.example.org\n", encoding="utf-8")
        result = self.run_build()
        self.assertEqual(result["rulesets"]["base"]["covered_rules_removed"], 1)
        self.assertEqual(result["rulesets"]["extra"]["covered_rules_removed"], 0)
        self.assertIn("DOMAIN,a.covered.example.org", builder.read_rules(self.output / "extra.list", "text"))


if __name__ == "__main__":
    unittest.main()
