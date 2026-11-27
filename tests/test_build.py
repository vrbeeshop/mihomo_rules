from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

from scripts import build as builder


def fixture_manifest():
    return {
        "version": 1,
        "repository": "owner/rules",
        "sources": {
            "domains": {"behavior": "domain", "format": "yaml", "url": "https://example.com/domains"},
            "classical-domains": {"behavior": "classical", "format": "text", "url": "https://example.com/classical-domains"},
            "networks": {"behavior": "ipcidr", "format": "text", "url": "https://example.com/networks"},
            "other": {"behavior": "classical", "format": "yaml", "url": "https://example.com/other"},
        },
        "rulesets": {
            "combined": {"behavior": "domain", "sources": ["domains", "classical-domains"]},
            "networks": {"behavior": "ipcidr", "sources": ["networks"]},
            "other": {"behavior": "classical", "sources": ["other"]},
        },
    }


class ParsingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def read(self, content, format_="text"):
        path = self.directory / f"source.{format_}"
        path.write_text(content, encoding="utf-8")
        return builder.read_rules(path, format_)

    def test_text_comments_bom_and_whitespace(self):
        self.assertEqual(
            self.read("\ufeff# comment\n// comment\n\n  Exact.example \n +.suffix.example\n"),
            ["Exact.example", "+.suffix.example"],
        )

    def test_yaml_quoted_rules_and_comments(self):
        self.assertEqual(
            self.read("payload:\n  - '+.example.com'\n  - '*.wild.example' # comment\n  - '# ignored'\n", "yaml"),
            ["+.example.com", "*.wild.example"],
        )

    def test_empty_and_malformed_sources_fail(self):
        cases = [
            ("", "text"), ("# comment\n// comment\n", "text"),
            ("", "yaml"), ("payload: []", "yaml"), ("payload: example.com", "yaml"),
            ("- example.com", "yaml"), ("payload: [123]", "yaml"),
            ("payload: [null]", "yaml"), ("payload: [", "yaml"),
            ('payload: ["first\\nsecond"]', "yaml"), ("bad\x00.example", "text"),
        ]
        for content, format_ in cases:
            with self.subTest(content=content, format_=format_):
                with self.assertRaises((builder.BuildError, yaml.YAMLError)):
                    self.read(content, format_)

    def test_domain_matching_prefixes_are_not_conflated(self):
        for rule in ("Exact.Example", "+.Inclusive.Example", ".Exclusive.Example", "*.Wild.Example"):
            with self.subTest(rule=rule):
                self.assertEqual(builder.normalize_rule(rule, "domain", "domain"), rule.lower())
        self.assertEqual(builder.normalize_rule("DOMAIN, Example.COM", "classical", "domain"), "example.com")
        self.assertEqual(builder.normalize_rule("DOMAIN-SUFFIX, Example.COM", "classical", "domain"), "+.example.com")

    def test_unrepresentable_classical_rules_cannot_be_converted(self):
        rules = [
            "DOMAIN-KEYWORD,example", "DOMAIN-REGEX,.*example.*",
            "IP-CIDR,192.0.2.0/24", "IP-CIDR6,2001:db8::/32,no-resolve",
            "PROCESS-NAME,example.exe", "PROCESS-PATH,/opt/example", "GEOIP,CN",
            "DOMAIN,example.com,DIRECT", "DOMAIN-SUFFIX,example.com,no-resolve",
            "AND,((DOMAIN,example.com),(NETWORK,udp))", "DOMAIN,",
        ]
        for rule in rules:
            with self.subTest(rule=rule):
                with self.assertRaises(builder.BuildError):
                    builder.normalize_rule(rule, "classical", "domain")

    def test_classical_literals_cannot_acquire_wildcard_or_suffix_meaning(self):
        # Classical DOMAIN / DOMAIN-SUFFIX treats these as literals; the
        # domain provider grammar would reinterpret them as matching patterns.
        literals = ["", ".ua", "example.com.", "example..com", "*.example.com",
                    "+.example.com", "foo*bar.example", "foo+bar.example", "*", "+"]
        for kind in ("DOMAIN", "DOMAIN-SUFFIX"):
            for literal in literals:
                rule = f"{kind},{literal}"
                with self.subTest(rule=rule):
                    with self.assertRaisesRegex(builder.BuildError, "Classical literal"):
                        builder.normalize_rule(rule, "classical", "domain")
                    if literal:
                        self.assertEqual(builder.normalize_rule(rule, "classical", "classical"), rule)

    def test_invalid_domain_and_cidr_rules_fail(self):
        for rule in ("", "has space.example", "https://example.com", "example.com/path", "example.com#comment", "DOMAIN,example.com"):
            with self.subTest(rule=rule):
                with self.assertRaises(builder.BuildError):
                    builder.normalize_rule(rule, "domain", "domain")
        for rule in ("example.com", "192.0.2.0/33", "2001:db8::/129", "IP-CIDR,192.0.2.0/24"):
            with self.subTest(rule=rule):
                with self.assertRaises(builder.BuildError):
                    builder.normalize_rule(rule, "ipcidr", "ipcidr")

    def test_cidr_normalization_and_classical_options(self):
        self.assertEqual(builder.normalize_rule("192.0.2.123/24", "ipcidr", "ipcidr"), "192.0.2.0/24")
        self.assertEqual(builder.normalize_rule("2001:DB8::1/64", "ipcidr", "ipcidr"), "2001:db8::/64")
        rule = "AND,((PROCESS-NAME,App.EXE),(NETWORK,udp))"
        self.assertEqual(builder.normalize_rule(rule, "classical", "classical"), rule)
        with self.assertRaises(builder.BuildError):
            builder.normalize_rule("192.0.2.0/24", "ipcidr", "domain")

    def test_manifest_accepts_supported_grouping(self):
        path = self.directory / "manifest.yaml"
        expected = fixture_manifest()
        path.write_text(yaml.safe_dump(expected), encoding="utf-8")
        self.assertEqual(builder.load_manifest(path), expected)

    def test_classical_export_preserves_domain_scope_and_ip_networks(self):
        for rule, source, expected in (
            ("exact.example", "domain", "DOMAIN,exact.example"),
            ("+.suffix.example", "domain", "DOMAIN-SUFFIX,suffix.example"),
            ("2001:db8::1/64", "ipcidr", "IP-CIDR,2001:db8::/64"),
        ):
            self.assertEqual(builder.normalize_rule(rule, source, "classical"), expected)
        for pattern in (".example", "*.example", "*"):
            with self.assertRaises(builder.BuildError):
                builder.normalize_rule(pattern, "domain", "classical")

    def test_manifest_accepts_local_sources_and_exact_exclusions_without_rewriting(self):
        manifest = fixture_manifest()
        manifest["sources"]["domains"] = {
            "behavior": "domain", "format": "yaml", "path": "rules/vrbee_proxy.yaml",
            "exclude_rules": ["+.excluded.example"],
        }
        manifest["sources"]["classical-domains"] = {
            "behavior": "classical", "format": "text", "path": "rules/vrbee_direct.list",
        }
        path = self.directory / "manifest.yaml"
        path.write_text(yaml.safe_dump(manifest), encoding="utf-8")
        self.assertEqual(builder.load_manifest(path), manifest)

    def test_cli_resolves_local_sources_relative_to_manifest(self):
        manifest = fixture_manifest()
        manifest["sources"]["domains"] = {
            "behavior": "domain", "format": "yaml", "path": "rules/vrbee_proxy.yaml",
        }
        path = self.directory / "manifest.yaml"
        path.write_text(yaml.safe_dump(manifest), encoding="utf-8")
        argv = ["build.py", "--manifest", str(path), "--output", str(self.directory / "generated")]
        with patch("sys.argv", argv), patch.object(builder, "build", return_value={"rulesets": {}}) as build, redirect_stdout(io.StringIO()):
            builder.main()
        self.assertEqual(build.call_args.kwargs["source_root"], path.parent)

    def test_cli_rejects_source_roots_and_hidden_output_directories(self):
        manifest = self.directory / "manifest.yaml"
        work = self.directory / "cache"
        outputs = [self.directory, self.directory.parent, work,
                   self.directory / ".internal", self.directory / ".internal" / "generated"]
        for output in outputs:
            with self.subTest(output=output):
                argv = ["build.py", "--manifest", str(manifest), "--work-dir", str(work),
                        "--output", str(output)]
                with patch("sys.argv", argv), patch.object(builder, "build") as build, redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        builder.main()
                self.assertEqual(error.exception.code, 1)
                build.assert_not_called()

    def test_manifest_rejects_ambiguous_sources_and_invalid_exclusions(self):
        invalid = [
            {"url": "https://example.com/rules", "path": "rules/test.yaml"},
            {}, {"path": None},
        ]
        invalid.extend({"url": "https://example.com/rules", "exclude_rules": value}
                       for value in (None, "example.com", [None], [123], [{}], [""],
                                     [" example.com"], ["first\nsecond"], ["bad\x00rule"]))
        for fields in invalid:
            with self.subTest(fields=fields):
                manifest = fixture_manifest()
                manifest["sources"]["domains"] = {"behavior": "domain", "format": "yaml", **fields}
                path = self.directory / "manifest.yaml"
                path.write_text(yaml.safe_dump(manifest), encoding="utf-8")
                with self.assertRaises(builder.BuildError):
                    builder.load_manifest(path)

    def test_manifest_rejects_paths_outside_rules_and_mismatched_formats(self):
        for value in ("/rules/test.yaml", "../rules/test.yaml", ".internal/test.yaml",
                      "rules/../secret.yaml", "rules/./test.yaml", "rules//test.yaml",
                      "rules\\test.yaml", "rules/test.list", "rules/test.mrs"):
            with self.subTest(path=value):
                manifest = fixture_manifest()
                manifest["sources"]["domains"] = {"behavior": "domain", "format": "yaml", "path": value}
                path = self.directory / "manifest.yaml"
                path.write_text(yaml.safe_dump(manifest), encoding="utf-8")
                with self.assertRaises(builder.BuildError):
                    builder.load_manifest(path)

    def test_local_source_symlink_cannot_escape_rules_directory(self):
        rules = self.directory / "rules"
        rules.mkdir()
        secret = self.directory / "secret.yaml"
        secret.write_text("payload: [private.example]\n", encoding="utf-8")
        (rules / "source.yaml").symlink_to(secret)
        source = {"behavior": "domain", "format": "yaml", "path": "rules/source.yaml"}
        with self.assertRaisesRegex(builder.BuildError, "escapes rules"):
            builder.local_source_path(source, self.directory)
        manifest = fixture_manifest()
        manifest["sources"]["domains"] = source
        path = self.directory / "manifest.yaml"
        path.write_text(yaml.safe_dump(manifest), encoding="utf-8")
        with self.assertRaisesRegex(builder.BuildError, "escapes rules"):
            builder.load_manifest(path)

    def test_manifest_rejects_invalid_grouping(self):
        cases = []
        for sources in ([], ["missing"], ["domains", "domains"], "domains"):
            value = fixture_manifest()
            value["rulesets"]["combined"]["sources"] = sources
            cases.append(value)
        value = fixture_manifest()
        value["rulesets"]["combined"]["behavior"] = "ipcidr"
        cases.append(value)
        value = fixture_manifest()
        value["rulesets"]["networks"]["behavior"] = "domain"
        cases.append(value)
        for field, value in (("format", "csv"), ("url", "http://example.com/rules"), ("behavior", "unknown")):
            manifest = fixture_manifest()
            manifest["sources"]["domains"][field] = value
            cases.append(manifest)
        value = fixture_manifest()
        value["sources"]["other"]["format"] = "mrs"
        cases.append(value)
        for value in cases:
            with self.subTest(manifest=value):
                path = self.directory / "manifest.yaml"
                path.write_text(yaml.safe_dump(value), encoding="utf-8")
                with self.assertRaises(builder.BuildError):
                    builder.load_manifest(path)


class MihomoExecutionTests(unittest.TestCase):
    def test_success_exit_with_skipped_rule_is_failure(self):
        messages = [
            'time="now" level=warning msg="skip invalid rule"',
            'time="now" level=error msg="invalid Ipcidr"',
            "skip invalid domain", "invalid Ipcidr: bad",
            "parse classical rule unexpected error", "level=fatal",
        ]
        for message in messages:
            with self.subTest(message=message):
                result = subprocess.CompletedProcess([], 0, "", message)
                with patch.object(builder.subprocess, "run", return_value=result):
                    with self.assertRaises(builder.BuildError):
                        builder.run_mihomo(Path("mihomo"), ["convert-ruleset", "domain", "text"])

    def test_nonzero_exit_is_failure_even_without_output(self):
        result = subprocess.CompletedProcess([], 1, "", "")
        with patch.object(builder.subprocess, "run", return_value=result):
            with self.assertRaises(builder.BuildError):
                builder.run_mihomo(Path("mihomo"), ["-t"])


class DownloadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.destination = Path(self.temporary.name) / "source.list"

    @staticmethod
    def response(content, url="https://example.com/rules"):
        response = io.BytesIO(content)
        response.url = url
        return response

    def test_transient_failure_retries_then_saves_source(self):
        attempts = [builder.urllib.error.URLError("temporary failure"), self.response(b"example.com\n")]
        with patch.object(builder.urllib.request, "urlopen", side_effect=attempts) as opener, patch.object(builder.time, "sleep"):
            builder.download("https://example.com/rules", self.destination)
        self.assertEqual(opener.call_count, 2)
        self.assertEqual(self.destination.read_bytes(), b"example.com\n")

    def test_failed_download_does_not_write_partial_source(self):
        with patch.object(builder.urllib.request, "urlopen", side_effect=builder.urllib.error.URLError("unavailable")) as opener, patch.object(builder.time, "sleep"):
            with self.assertRaisesRegex(builder.BuildError, "Download failed"):
                builder.download("https://example.com/rules", self.destination)
        self.assertEqual(opener.call_count, 3)
        self.assertFalse(self.destination.exists())

    def test_empty_source_and_https_downgrade_fail(self):
        for content, url in ((b"", "https://example.com/rules"), (b"example.com\n", "http://example.com/rules")):
            with self.subTest(content=content, url=url):
                with patch.object(builder.urllib.request, "urlopen", return_value=self.response(content, url)):
                    with self.assertRaises(builder.BuildError):
                        builder.download("https://example.com/rules", self.destination)
                self.assertFalse(self.destination.exists())


class GeodataValidationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.output = self.directory / "dist"
        self.work = self.directory / "validation"
        self.cache = self.directory / "geodata"
        self.output.mkdir()
        self.work.mkdir()
        self.groups = {"local": {"behavior": "classical"}}
        (self.output / "local.yaml").write_text(yaml.safe_dump({"payload": [
            "AND,((GEOSITE,google),(OR,((IP-ASN,AS32934),(SRC-GEOIP,US))))",
        ]}), encoding="utf-8")
        self.databases = {"GeoSite.dat", "Country.mmdb", "ASN.mmdb"}

    def cache_databases(self):
        self.cache.mkdir()
        for name in self.databases:
            path = self.cache / name
            path.write_bytes(f"validated {name}".encode())
            metadata = {"sha256": builder.sha256(path), "bytes": path.stat().st_size}
            (self.cache / f"{name}.json").write_text(json.dumps(metadata), encoding="utf-8")

    def validate(self, *, offline=False):
        return builder.validate_providers(Path("mihomo"), self.output, self.groups, self.work,
                                          self.cache, offline=offline)

    def test_detects_direct_and_nested_dependencies_without_matching_regex_text(self):
        self.assertEqual(builder.required_geodata(["GEOSITE,google", "GEOIP,US"]),
                         {"GeoSite.dat", "Country.mmdb"})
        self.assertEqual(builder.required_geodata(["SRC-IP-ASN,AS32934"]), {"ASN.mmdb"})
        self.assertEqual(builder.required_geodata([
            "AND,((GEOSITE,google),(NOT,((SRC-IP-ASN,AS32934))))",
            "OR,((GEOIP,US),(IP-ASN,AS12345))",
        ]), self.databases)
        self.assertEqual(builder.required_geodata(["DOMAIN-REGEX,^(GEOSITE,google)$"]), set())

    def test_online_caches_only_successfully_validated_databases_and_reports_hashes(self):
        def native_validation(*_):
            for name in self.databases:
                (self.work / name).write_bytes(f"downloaded {name}".encode())
        with patch.object(builder, "run_mihomo", side_effect=native_validation):
            result = self.validate()
        self.assertEqual(set(result), self.databases)
        for name, metadata in result.items():
            self.assertEqual((self.cache / name).read_bytes(), (self.work / name).read_bytes())
            self.assertEqual(metadata["sha256"], builder.sha256(self.work / name))
            self.assertEqual(json.loads((self.cache / f"{name}.json").read_text()), metadata)
        previous = {path.name: path.read_bytes() for path in self.cache.iterdir()}
        with patch.object(builder, "run_mihomo", side_effect=builder.BuildError("invalid geodata")):
            with self.assertRaisesRegex(builder.BuildError, "invalid geodata"):
                self.validate()
        self.assertEqual({path.name: path.read_bytes() for path in self.cache.iterdir()}, previous)

    def test_offline_copies_verified_databases_and_disables_network_fallback(self):
        self.cache_databases()
        with patch.object(builder, "run_mihomo") as native:
            result = self.validate(offline=True)
        native.assert_called_once()
        self.assertEqual(set(result), self.databases)
        for name in self.databases:
            self.assertEqual((self.work / name).read_bytes(), (self.cache / name).read_bytes())
        config = yaml.safe_load((self.work / "validate.yaml").read_text())
        self.assertFalse(config["geodata-mode"])
        self.assertFalse(config["geo-auto-update"])
        self.assertTrue(all(url == "offline://disabled" for url in config["geox-url"].values()))

    def test_offline_missing_or_tampered_database_fails_before_native_validation(self):
        with patch.object(builder, "run_mihomo") as native:
            with self.assertRaisesRegex(builder.BuildError, "No cached validation geodata"):
                self.validate(offline=True)
            native.assert_not_called()
        self.cache_databases()
        (self.cache / "ASN.mmdb").write_bytes(b"tampered")
        with patch.object(builder, "run_mihomo") as native:
            with self.assertRaisesRegex(builder.BuildError, "cache hash mismatch"):
                self.validate(offline=True)
            native.assert_not_called()


class NativeBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured = os.environ.get("MIHOMO_BIN")
        cls.binary = Path(configured or ".work/bin/mihomo").resolve()
        if not cls.binary.is_file():
            if configured:
                raise AssertionError(f"MIHOMO_BIN does not exist: {cls.binary}")
            raise unittest.SkipTest("Install Mihomo with scripts/install_mihomo.py for native integration tests")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.output = self.directory / "dist"
        self.work = self.directory / "work"
        self.manifest = fixture_manifest()
        self.fixtures = {
            "https://example.com/domains": b"payload:\n  - Exact.Example\n  - +.suffix.example\n  - .subdomains.example\n  - '*.wild.example'\n  - exact.example\n",
            "https://example.com/classical-domains": b"DOMAIN,EXACT.EXAMPLE\nDOMAIN-SUFFIX,suffix.example\nDOMAIN,additional.example\n",
            "https://example.com/networks": b"192.0.2.1/25\n192.0.2.128/25\n2001:db8::1/64\n2001:db8::/64\n",
            "https://example.com/other": b"payload:\n  - DOMAIN-KEYWORD,First\n  - PROCESS-NAME,Example.EXE\n  - IP-CIDR,198.51.100.0/24,no-resolve\n  - DOMAIN-KEYWORD,First\n",
        }

    def fetch(self, url, destination, **_):
        destination.write_bytes(self.fixtures[url])

    def build(self, *, offline=False):
        with patch.object(builder, "download", side_effect=self.fetch), redirect_stdout(io.StringIO()):
            return builder.build(self.manifest, self.binary, self.output, self.work, offline=offline,
                                 source_root=self.directory)

    def snapshot(self):
        return {path.name: path.read_bytes() for path in self.output.iterdir()}

    def test_native_roundtrip_preserves_domain_prefixes_and_ipv6(self):
        domains = ["exact.example", "+.inclusive.example", ".exclusive.example", "*.wild.example"]
        self.assertEqual(
            builder.compile_rules(self.binary, "domain", domains, self.directory, "domain"),
            sorted(domains),
        )
        self.assertEqual(
            builder.compile_rules(self.binary, "ipcidr", ["192.0.2.0/25", "192.0.2.128/25", "2001:db8::/64"], self.directory, "ip"),
            ["192.0.2.0/24", "2001:db8::/64"],
        )

    def test_full_build_removes_duplicates_and_exports_matching_formats(self):
        self.manifest["mirror"] = ["networks", "other"]
        result = self.build()
        self.assertEqual(result["mirror_files"], ["networks.mrs", "other.yaml"])
        expected = ["*.wild.example", "+.suffix.example", ".subdomains.example", "additional.example", "exact.example"]
        self.assertEqual(builder.read_rules(self.output / "combined.list", "text"), expected)
        self.assertEqual(builder.read_rules(self.output / "combined.yaml", "yaml"), expected)
        self.assertEqual(result["rulesets"]["combined"]["exact_duplicates_removed"], 3)
        self.assertEqual(result["rulesets"]["combined"]["sources"], ["domains", "classical-domains"])
        self.assertEqual(builder.read_rules(self.output / "networks.list", "text"), ["192.0.2.0/24", "2001:db8::/64"])
        self.assertEqual(result["rulesets"]["networks"]["exact_duplicates_removed"], 1)
        classical = ["DOMAIN-KEYWORD,First", "PROCESS-NAME,Example.EXE", "IP-CIDR,198.51.100.0/24,no-resolve"]
        self.assertEqual(builder.read_rules(self.output / "other.list", "text"), classical)
        self.assertEqual(builder.read_rules(self.output / "other.yaml", "yaml"), classical)
        self.assertFalse((self.output / "other.mrs").exists())
        self.assertEqual(result["rulesets"]["other"]["exact_duplicates_removed"], 1)
        providers = yaml.safe_load((self.output / "providers.yaml").read_text())["rule-providers"]
        self.assertEqual(providers["combined"]["url"], "https://github.com/owner/rules/releases/latest/download/combined.mrs")
        self.assertEqual(providers["other"]["format"], "yaml")
        for entry in (self.output / "checksums.sha256").read_text().splitlines():
            digest, name = entry.split("  ", 1)
            self.assertEqual(builder.sha256(self.output / name), digest)
        for ruleset in result["rulesets"].values():
            for name, info in ruleset["files"].items():
                self.assertEqual(builder.sha256(self.output / name), info["sha256"])
        self.assertEqual(json.loads((self.output / "manifest.json").read_text()), result)

    def test_rule_artifacts_are_deterministic_across_input_order(self):
        first = self.build()
        before = self.snapshot()
        self.fixtures["https://example.com/domains"] = b"payload:\n  - exact.example\n  - '*.wild.example'\n  - .subdomains.example\n  - +.suffix.example\n  - Exact.Example\n"
        self.fixtures["https://example.com/networks"] = b"2001:db8::/64\n2001:db8::1/64\n192.0.2.128/25\n192.0.2.1/25\n"
        second = self.build()
        for group in ("combined", "networks", "other"):
            self.assertEqual(first["rulesets"][group], second["rulesets"][group])
            for ext in ("list", "yaml", "mrs"):
                name = f"{group}.{ext}"
                if name in before:
                    self.assertEqual((self.output / name).read_bytes(), before[name])

    def test_long_classical_rule_stays_on_one_yaml_line(self):
        rule = "PROCESS-NAME," + "Long Application Name " * 8 + "Client.exe"
        self.fixtures["https://example.com/other"] = yaml.safe_dump({"payload": [rule]}).encode("utf-8")
        self.build()
        output = (self.output / "other.yaml").read_text(encoding="utf-8")
        # Mihomo consumes provider YAML one rule per physical line; merely
        # recovering the original value with a YAML parser is insufficient.
        self.assertEqual(output.splitlines(), ["payload:", f"- {rule}"])
        self.assertEqual(builder.read_rules(self.output / "other.list", "text"), [rule])

    def test_failure_keeps_previous_successful_output(self):
        self.build()
        previous = self.snapshot()
        with patch.object(builder, "download", side_effect=builder.BuildError("upstream unavailable")), redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(builder.BuildError, "upstream unavailable"):
                builder.build(self.manifest, self.binary, self.output, self.work)
        self.assertEqual(self.snapshot(), previous)
        self.fixtures["https://example.com/classical-domains"] = b"DOMAIN-KEYWORD,unrepresentable\n"
        with self.assertRaisesRegex(builder.BuildError, "Cannot losslessly convert"):
            self.build()
        self.assertEqual(self.snapshot(), previous)

    def test_provider_validation_failure_keeps_previous_output(self):
        self.build()
        previous = self.snapshot()
        self.fixtures["https://example.com/other"] = b"payload:\n  - NOT-A-REAL-RULE,something\n"
        with self.assertRaises(builder.BuildError):
            self.build()
        self.assertEqual(self.snapshot(), previous)

    def test_standalone_build_rejects_nested_global_geodata_before_native_validation(self):
        self.manifest["allow_global_geodata"] = False
        self.fixtures["https://example.com/other"] = b"payload: ['NOT,((GEOSITE,example))']\n"
        with patch.object(builder, "validate_providers") as validate:
            with self.assertRaisesRegex(builder.BuildError, "other requires global geodata: GeoSite.dat"):
                self.build()
        validate.assert_not_called()

    def test_native_warning_about_invalid_domain_rejects_entire_build(self):
        self.build()
        previous = self.snapshot()
        # Mihomo can compile the valid entries while skipping a bad domain.
        self.fixtures["https://example.com/domains"] = b"payload:\n  - valid.example\n  - invalid.example.\n"
        with self.assertRaisesRegex(builder.BuildError, "skip invalid domain"):
            self.build()
        self.assertEqual(self.snapshot(), previous)

    def test_mrs_sources_are_decoded_and_merged(self):
        builder.compile_rules(self.binary, "domain", ["+.mrs.example", "exact.example"], self.directory, "upstream")
        self.manifest["sources"]["domains"]["format"] = "mrs"
        self.fixtures["https://example.com/domains"] = (self.directory / "upstream.mrs").read_bytes()
        self.build()
        self.assertEqual(builder.read_rules(self.output / "combined.list", "text"),
                         ["+.mrs.example", "+.suffix.example", "additional.example", "exact.example"])

    def test_offline_local_sources_use_current_files_without_download_or_cache(self):
        rules = self.directory / "rules"
        rules.mkdir()
        local = rules / "vrbee_proxy.yaml"
        local.write_text("payload: [before.example]\n", encoding="utf-8")
        self.manifest["sources"] = {
            "local": {"behavior": "domain", "format": "yaml", "path": "rules/vrbee_proxy.yaml"},
        }
        self.manifest["rulesets"] = {"vrbee_proxy": {"behavior": "domain", "sources": ["local"]}}
        with patch.object(builder, "download", side_effect=AssertionError("local build downloaded")), redirect_stdout(io.StringIO()):
            first = builder.build(self.manifest, self.binary, self.output, self.work, offline=True,
                                  source_root=self.directory)
            local.write_text("payload: [after.example]\n", encoding="utf-8")
            second = builder.build(self.manifest, self.binary, self.output, self.work, offline=True,
                                   source_root=self.directory)
        self.assertFalse((self.work / "sources").exists())
        self.assertEqual(builder.read_rules(self.output / "vrbee_proxy.yaml", "yaml"), ["after.example"])
        metadata = second["sources"]["local"]
        self.assertEqual(metadata["path"], "rules/vrbee_proxy.yaml")
        self.assertNotIn("url", metadata)
        self.assertEqual(metadata["sha256"], builder.sha256(local))
        self.assertNotEqual(first["sources"]["local"]["sha256"], metadata["sha256"])

    def test_local_classical_list_preserves_options_and_exports_yaml_and_list(self):
        rules = self.directory / "rules"
        rules.mkdir()
        local = rules / "vrbee_extra.list"
        expected = ["PROCESS-NAME,Client.EXE", "IP-CIDR,198.51.100.0/24,no-resolve"]
        local.write_text("\n".join(expected) + "\n", encoding="utf-8")
        self.manifest["sources"]["other"] = {
            "behavior": "classical", "format": "text", "path": "rules/vrbee_extra.list",
        }
        self.build()
        self.assertEqual(builder.read_rules(self.output / "other.yaml", "yaml"), expected)
        self.assertEqual(builder.read_rules(self.output / "other.list", "text"), expected)
        self.assertFalse((self.output / "other.mrs").exists())
        self.assertFalse((self.work / "sources" / "other.text").exists())

    def test_exclusions_are_exact_before_normalization_and_report_removed_entries(self):
        self.fixtures["https://example.com/domains"] = (
            b"payload: [remove.example, Remove.example, remove.example.net, remove.example]\n"
        )
        self.manifest["sources"]["domains"]["exclude_rules"] = ["remove.example"]
        self.fixtures["https://example.com/classical-domains"] += b"DOMAIN-SUFFIX,.ua\n"
        self.manifest["sources"]["classical-domains"]["exclude_rules"] = ["DOMAIN-SUFFIX,.ua"]
        result = self.build()
        output = builder.read_rules(self.output / "combined.list", "text")
        self.assertIn("remove.example", output)  # The differently cased input remains.
        self.assertIn("remove.example.net", output)
        self.assertNotIn("+.ua", output)
        metadata = result["sources"]["domains"]
        self.assertEqual(metadata["input_rules"], 4)
        self.assertEqual(metadata["excluded_rules"], ["remove.example", "remove.example"])
        self.assertEqual(metadata["excluded_rules_count"], 2)
        self.assertEqual(metadata["rules"], 2)

    def test_mrs_exclusions_apply_after_decoding(self):
        builder.compile_rules(self.binary, "domain", ["+.mrs.example", "exact.example"], self.directory, "upstream")
        self.manifest["sources"]["domains"].update(format="mrs", exclude_rules=["+.mrs.example"])
        self.fixtures["https://example.com/domains"] = (self.directory / "upstream.mrs").read_bytes()
        result = self.build()
        self.assertNotIn("+.mrs.example", builder.read_rules(self.output / "combined.list", "text"))
        self.assertEqual(result["sources"]["domains"]["excluded_rules"], ["+.mrs.example"])

    def test_empty_effective_source_preserves_previous_successful_output(self):
        self.build()
        previous = self.snapshot()
        self.fixtures["https://example.com/domains"] = b"payload: [excluded.example]\n"
        self.manifest["sources"]["domains"]["exclude_rules"] = ["excluded.example"]
        with self.assertRaisesRegex(builder.BuildError, "Empty effective rule list"):
            self.build()
        self.assertEqual(self.snapshot(), previous)

    def test_offline_cache_requires_matching_hash_and_url(self):
        self.build()
        with patch.object(builder, "download", side_effect=AssertionError("offline build downloaded")), redirect_stdout(io.StringIO()):
            result = builder.build(self.manifest, self.binary, self.output, self.work, offline=True)
        self.assertTrue(result["offline"])
        previous = self.snapshot()
        cached = self.work / "sources" / "domains.yaml"
        cached.write_text("payload: [tampered.example]\n")
        with self.assertRaisesRegex(builder.BuildError, "Cache provenance mismatch"):
            self.build(offline=True)
        self.assertEqual(self.snapshot(), previous)
        self.build()
        self.manifest["sources"]["domains"]["url"] = "https://example.com/replaced-source"
        with self.assertRaisesRegex(builder.BuildError, "Cache provenance mismatch"):
            self.build(offline=True)


if __name__ == "__main__":
    unittest.main()
