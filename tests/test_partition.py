from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import tempfile
import unittest

import yaml

from scripts import build as builder


def manifest():
    return {"version": 1, "repository": "owner/rules", "sources": {
        name: {"behavior": "classical", "format": "text", "path": "rules/common.list", "partition": partition}
        for name, partition in (("domains", "domain"), ("extra", "remainder"))}, "rulesets": {
            "domains": {"behavior": "domain", "sources": ["domains"]},
            "extra": {"behavior": "classical", "sources": ["extra"]}}}


class PartitionTests(unittest.TestCase):
    def test_partitions_are_disjoint_complete_and_preserve_order(self):
        domains = ["DOMAIN,Exact.Example", "DOMAIN-SUFFIX,suffix.example", "DOMAIN, Exact.Example"]
        remainder = ["DOMAIN-SUFFIX,.example", "DOMAIN,*.example", "DOMAIN,example.",
                     "DOMAIN-SUFFIX,example,no-resolve", "DOMAIN-KEYWORD,example",
                     "PROCESS-NAME,Client.EXE", "IP-CIDR,192.0.2.0/24,no-resolve",
                     "AND,((NETWORK,udp),(DST-PORT,443))"]
        rules = domains[:1] + remainder[:3] + domains[1:] + remainder[3:]
        self.assertEqual(builder.partition_rules(rules, "domain"), domains)
        self.assertEqual(builder.partition_rules(rules, "remainder"), remainder)
        self.assertEqual(len(rules), len(domains) + len(remainder))
        for rule in domains:
            builder.normalize_rule(rule, "classical", "domain")
        for rule in remainder:
            with self.subTest(rule=rule), self.assertRaises(builder.BuildError):
                builder.normalize_rule(rule, "classical", "domain")

    def test_partition_validation_rejects_unknown_values_and_incompatible_sources(self):
        cases = [{"partition": value} for value in (None, "", "all", [], {})]
        cases += [{"behavior": behavior} for behavior in ("domain", "ipcidr")]
        cases += [{"format": "mrs", "url": "https://example.org/source.mrs"}]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.yaml"
            for changes in cases:
                with self.subTest(changes=changes):
                    value = manifest()
                    source = value["sources"]["domains"]
                    if "url" in changes:
                        del source["path"]
                    source.update(changes)
                    path.write_text(yaml.safe_dump(value), encoding="utf-8")
                    with self.assertRaises(builder.BuildError):
                        builder.load_manifest(path)
        with self.assertRaises(builder.BuildError):
            builder.partition_rules(["DOMAIN,example.org"], "unknown")

    def test_both_partitions_can_read_one_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.yaml"
            value = manifest()
            path.write_text(yaml.safe_dump(value), encoding="utf-8")
            self.assertEqual(builder.load_manifest(path), value)

    def test_internal_coverage_preserves_other_rules_and_survivor_order(self):
        rules = ["DOMAIN,child.example.org", "PROCESS-NAME,Client.EXE",
                 "DOMAIN-SUFFIX,child.example.org", "IP-CIDR,192.0.2.0/24,no-resolve",
                 "DOMAIN-SUFFIX,example.org", "DOMAIN-KEYWORD,example",
                 "DOMAIN-SUFFIX,EXAMPLE.ORG", "DOMAIN,other.example.net",
                 "DOMAIN,OTHER.EXAMPLE.NET", "DOMAIN-SUFFIX,.org",
                 "DOMAIN-SUFFIX,*.org", r"DOMAIN-REGEX,\Aexample\.org\z",
                 "AND,((NETWORK,udp),(DST-PORT,443))",
                 "DOMAIN,later.example.org", "DOMAIN-SUFFIX,later.example.org"]
        self.assertEqual(builder.remove_internal_coverage(rules, "classical"),
                         [rules[index] for index in (0, 1, 2, 3, 4, 5, 7, 9, 10, 11, 12)])
        self.assertEqual(builder.remove_internal_coverage(rules, "domain"), rules)


class NativePartitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured = os.environ.get("MIHOMO_BIN")
        cls.binary = Path(configured or ".work/bin/mihomo").resolve()
        if not cls.binary.is_file():
            if configured:
                raise AssertionError(f"MIHOMO_BIN does not exist: {cls.binary}")
            raise unittest.SkipTest("Install Mihomo for native integration tests")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "rules").mkdir()
        self.source = self.root / "rules/common.list"
        self.output = self.root / "dist"
        self.manifest = manifest()
        self.rules = ["DOMAIN-SUFFIX,example.org", "DOMAIN,exact.example.net",
                      "DOMAIN,exact.example.net", "PROCESS-NAME,Client.EXE",
                      "DOMAIN-KEYWORD,service", "IP-CIDR,192.0.2.0/24,no-resolve"]
        builder.write_list(self.source, self.rules)

    def build(self):
        with redirect_stdout(io.StringIO()):
            return builder.build(self.manifest, self.binary, self.output, self.root / "work",
                                 offline=True, source_root=self.root)

    def test_one_source_produces_domain_mrs_and_classical_remainder(self):
        original = self.source.read_bytes()
        result = self.build()
        self.assertTrue((self.output / "domains.mrs").is_file())
        self.assertFalse((self.output / "extra.mrs").exists())
        for format_, suffix in (("text", "list"), ("yaml", "yaml")):
            self.assertEqual(builder.read_rules(self.output / f"domains.{suffix}", format_),
                             ["+.example.org", "exact.example.net"])
            self.assertEqual(builder.read_rules(self.output / f"extra.{suffix}", format_), self.rules[3:])
        for name, partition in (("domains", "domain"), ("extra", "remainder")):
            source = result["sources"][name]
            self.assertEqual(source["input_rules"], 6)
            self.assertEqual(source["partition"], partition)
            self.assertEqual(source["partitioned_out_rules_count"], 3)
            self.assertEqual(source["rules"], 3)
        self.assertEqual(result["rulesets"]["domains"]["exact_duplicates_removed"], 1)
        self.assertEqual(self.source.read_bytes(), original)

    def test_exclusions_happen_before_partition_and_current_edits_are_used(self):
        self.build()
        builder.write_list(self.source, self.rules + ["DOMAIN,new.example.net"])
        for source in self.manifest["sources"].values():
            source["exclude_rules"] = ["DOMAIN,exact.example.net"]
        result = self.build()
        self.assertEqual(builder.read_rules(self.output / "domains.list", "text"),
                         ["+.example.org", "new.example.net"])
        for source in result["sources"].values():
            self.assertEqual(source["input_rules"], 7)
            self.assertEqual(source["excluded_rules_count"], 2)
            self.assertEqual(source["rules"] + source["partitioned_out_rules_count"], 5)

    def test_empty_partition_preserves_previous_successful_output(self):
        self.build()
        previous = (self.output / "manifest.json").read_bytes()
        builder.write_list(self.source, ["DOMAIN,only.example.org"])
        with self.assertRaisesRegex(builder.BuildError, "after partition"):
            self.build()
        self.assertEqual((self.output / "manifest.json").read_bytes(), previous)


if __name__ == "__main__":
    unittest.main()
