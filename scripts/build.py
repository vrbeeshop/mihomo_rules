#!/usr/bin/env python3
"""Build rule providers from upstream sources and repository rules/ files."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

import yaml


class BuildError(ValueError):
    pass


CLASSICAL_PARTITIONS = ("domain", "remainder", "domain-keyword")


def local_source_path(source: dict, source_root: Path) -> Path:
    """Resolve local sources within the rules/ directory."""
    value = source.get("path")
    if not isinstance(value, str) or "\\" in value:
        raise BuildError("Local source path must be a relative path under rules/")
    parts = value.split("/")
    if len(parts) < 2 or parts[0] != "rules" or any(part in ("", ".", "..") for part in parts):
        raise BuildError(f"Local source path must stay under rules/: {value!r}")
    expected_suffix = {"yaml": ".yaml", "text": ".list"}.get(source.get("format"))
    if expected_suffix is None or Path(value).suffix != expected_suffix:
        raise BuildError(f"Local source path must match its YAML or text format: {value!r}")
    root = source_root.resolve()
    candidate = (root / value).resolve()
    if not candidate.is_relative_to(root / "rules"):
        raise BuildError(f"Local source path escapes rules/: {value!r}")
    return candidate


def load_manifest(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != 1:
        raise BuildError("Expected manifest version: 1")
    if not isinstance(data.get("allow_global_geodata", True), bool):
        raise BuildError("allow_global_geodata must be a boolean")
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", data.get("repository", "")):
        raise BuildError("repository must be owner/repo")
    for section in ("sources", "rulesets"):
        if not isinstance(data.get(section), dict) or not data[section]:
            raise BuildError(f"Empty {section}")
        for name, item in data[section].items():
            if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", name):
                raise BuildError(f"Invalid {section} name: {name!r}")
            if not isinstance(item, dict) or item.get("behavior") not in ("domain", "ipcidr", "classical"):
                raise BuildError(f"Invalid behavior for {name}")
    for name, source in data["sources"].items():
        if source.get("format") not in ("mrs", "yaml", "text"):
            raise BuildError(f"Invalid format for {name}")
        if source["format"] == "mrs" and source["behavior"] == "classical":
            raise BuildError(f"MRS cannot contain classical rules: {name}")
        if "partition" in source and (source["partition"] not in CLASSICAL_PARTITIONS
                                      or source["behavior"] != "classical"):
            raise BuildError(f"Invalid classical source partition for {name}")
        if ("url" in source) == ("path" in source):
            raise BuildError(f"Expected exactly one of url or path for {name}")
        if "path" in source:
            local_source_path(source, path.parent)
        elif not isinstance(source["url"], str) or not source["url"].startswith("https://"):
            raise BuildError(f"Expected HTTPS URL for {name}")
        exclusions = source.get("exclude_rules", [])
        if not isinstance(exclusions, list) or any(
            not isinstance(rule, str) or not rule or rule != rule.strip()
            or any(c in rule for c in "\r\n\x00") for rule in exclusions
        ):
            raise BuildError(f"Expected exact rule strings in exclude_rules for {name}")
    for name, group in data["rulesets"].items():
        ids = group.get("sources")
        if not isinstance(ids, list) or not ids or len(ids) != len(set(ids)):
            raise BuildError(f"Invalid sources for {name}")
        for source_id in ids:
            if source_id not in data["sources"]:
                raise BuildError(f"Unknown source {source_id} in {name}")
            behavior = data["sources"][source_id]["behavior"]
            target = group["behavior"]
            if target not in (behavior, "classical") and (behavior, target) != ("classical", "domain"):
                raise BuildError(f"Incompatible behaviors for {name}: {source_id}")
    if "mirror" in data:
        names = data["mirror"]
        if (not isinstance(names, list) or not names
                or any(not isinstance(name, str) or name not in data["rulesets"] for name in names)
                or len(set(names)) != len(names)):
            raise BuildError("mirror must be a nonempty list of distinct ruleset names")
    ruleset_order(data["rulesets"])
    return data


def ruleset_order(groups: dict) -> list[str]:
    """Validate coverage dependencies and place each dependency before its users."""
    for name, group in groups.items():
        dependencies = group.get("exclude_covered_by", [])
        if not isinstance(dependencies, list) or any(not isinstance(item, str) for item in dependencies):
            raise BuildError(f"Expected ruleset names in exclude_covered_by for {name}")
        if len(dependencies) != len(set(dependencies)):
            raise BuildError(f"Duplicate coverage dependencies for {name}")
        for dependency in dependencies:
            if dependency not in groups:
                raise BuildError(f"Unknown coverage dependency {dependency} in {name}")
            if dependency == name:
                raise BuildError(f"Ruleset cannot exclude coverage by itself: {name}")
    ordered = []
    active = set()
    visited = set()

    def visit(name):
        if name in active:
            raise BuildError(f"Coverage dependency cycle at {name}")
        if name in visited:
            return
        active.add(name)
        for dependency in groups[name].get("exclude_covered_by", []):
            visit(dependency)
        active.remove(name)
        visited.add(name)
        ordered.append(name)

    for name in groups:
        visit(name)
    return ordered


def domain_pattern(rule: str, behavior: str) -> tuple[str, str] | None:
    """Recognize only domain forms whose containment can be established safely."""
    if behavior == "classical":
        parts = [part.strip() for part in rule.split(",")]
        if len(parts) != 2 or parts[0] not in ("DOMAIN", "DOMAIN-SUFFIX"):
            return None
        kind = "exact" if parts[0] == "DOMAIN" else "suffix"
        domain = parts[1]
    elif behavior == "domain":
        kind, domain = "exact", rule
        for prefix, prefix_kind in (("+.", "suffix"), ("*.", "single"), (".", "descendants")):
            if rule.startswith(prefix):
                kind, domain = prefix_kind, rule[len(prefix):]
                break
    else:
        return None
    # In classical rules, leading dots and wildcard characters are literals.
    # Other domain-provider patterns may have semantics outside these four forms.
    if not re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", domain):
        return None
    return kind, domain.lower()


class RuleCoverage:
    """Index one emitted ruleset without broadening any pattern's matching scope."""

    def __init__(self, behavior: str, rules: list[str]):
        self.behavior = behavior
        self.rules = set(rules)
        self.patterns = {kind: set() for kind in ("exact", "suffix", "descendants", "single")}
        for rule in rules:
            pattern = domain_pattern(rule, behavior)
            if pattern:
                kind, domain = pattern
                self.patterns[kind].add(domain)

    def covers(self, rule: str, behavior: str) -> bool:
        if behavior == self.behavior and rule in self.rules:
            return True
        pattern = domain_pattern(rule, behavior)
        if pattern is None:
            return False
        kind, domain = pattern
        labels = domain.split(".")
        suffixes = [".".join(labels[index:]) for index in range(len(labels))]
        if any(suffix in self.patterns["suffix"] for suffix in suffixes):
            return True
        # A descendant pattern excludes its own apex but includes every deeper name.
        if any(suffix in self.patterns["descendants"] for suffix in suffixes[1:]):
            return True
        if kind in ("descendants", "single") and domain in self.patterns["descendants"]:
            return True
        if kind == "exact":
            return (domain in self.patterns["exact"] or
                    len(suffixes) > 1 and suffixes[1] in self.patterns["single"])
        return kind == "single" and domain in self.patterns["single"]


def remove_covered_rules(rules: list[str], behavior: str,
                         dependencies: dict[str, RuleCoverage]) -> tuple[list[str], dict[str, int]]:
    kept = []
    covered_by = {}
    for rule in rules:
        for name, coverage in dependencies.items():
            if coverage.covers(rule, behavior):
                covered_by[name] = covered_by.get(name, 0) + 1
                break
        else:
            kept.append(rule)
    return kept, covered_by


def remove_internal_coverage(rules: list[str], behavior: str) -> list[str]:
    """Remove domains covered by earlier rules, preserving the first match point."""
    if behavior != "classical":
        return rules
    suffixes = set()
    seen = set()
    kept = []
    for rule in rules:
        pattern = domain_pattern(rule, behavior)
        if pattern is not None:
            kind, domain = pattern
            labels = domain.split(".")
            # Only earlier retained suffixes can make this entry redundant.
            # Moving a domain match later could trigger an intervening IP lookup.
            if pattern in seen or any(".".join(labels[index:]) in suffixes for index in range(len(labels))):
                continue
            seen.add(pattern)
            if kind == "suffix":
                suffixes.add(domain)
        kept.append(rule)
    return kept


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def download(url: str, destination: Path, attempts: int = 3) -> None:
    last_error = None
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "mihomo-rules-builder/1"})
            with urllib.request.urlopen(request, timeout=60) as response:
                if not response.url.startswith("https://"):
                    raise BuildError("Unexpected non-HTTPS redirect")
                raw = response.read(128 * 1024 * 1024 + 1)
            if not raw or len(raw) > 128 * 1024 * 1024:
                raise BuildError(f"Empty or oversized source: {url}")
            destination.write_bytes(raw)
            return
        except (OSError, urllib.error.URLError) as error:
            last_error = error
            if attempt + 1 < attempts:
                time.sleep(2 ** attempt)
    raise BuildError(f"Download failed: {url}: {last_error}")


def read_rules(path: Path, format_: str) -> list[str]:
    text = path.read_text(encoding="utf-8-sig")
    if format_ == "yaml":
        doc = yaml.safe_load(text)
        if not isinstance(doc, dict) or not isinstance(doc.get("payload"), list):
            raise BuildError(f"Expected YAML payload list: {path.name}")
        lines = doc["payload"]
    else:
        lines = text.splitlines()
    result = []
    for item in lines:
        if not isinstance(item, str):
            raise BuildError(f"Non-string rule in {path.name}")
        rule = item.strip()
        if rule and not rule.startswith(("#", "//")):
            if any(c in rule for c in "\r\n\x00"):
                raise BuildError(f"Invalid multiline rule in {path.name}")
            result.append(rule)
    if not result:
        raise BuildError(f"Empty rule list: {path.name}")
    return result


def normalize_rule(rule: str, source_behavior: str, target_behavior: str) -> str:
    # Older profiles consume combined classical providers. Expand the same
    # source data there while newer profiles can load the individual MRS files.
    if target_behavior == "classical" and source_behavior == "domain":
        pattern = domain_pattern(rule, "domain")
        if not pattern or pattern[0] not in ("exact", "suffix"):
            raise BuildError(f"Cannot losslessly convert domain pattern to classical: {rule}")
        kind, domain = pattern
        prefix = "DOMAIN" if kind == "exact" else "DOMAIN-SUFFIX"
        return f"{prefix},{domain}"
    if target_behavior == "classical" and source_behavior == "ipcidr":
        network = normalize_rule(rule, "ipcidr", "ipcidr")
        return f"IP-CIDR,{network}"
    if source_behavior == "classical" and target_behavior == "domain":
        parts = [part.strip() for part in rule.split(",")]
        if len(parts) != 2 or parts[0] not in ("DOMAIN", "DOMAIN-SUFFIX"):
            raise BuildError(f"Cannot losslessly convert classical rule to domain: {rule}")
        domain = parts[1]
        if not domain or domain.startswith(".") or domain.endswith(".") or ".." in domain or any(c in domain for c in "*+"):
            raise BuildError(f"Classical literal cannot be represented as a domain pattern: {rule}")
        rule = ("+." if parts[0] == "DOMAIN-SUFFIX" else "") + parts[1]
    elif source_behavior != target_behavior:
        raise BuildError(f"Cannot convert {source_behavior} to {target_behavior}")
    if target_behavior == "domain":
        if not rule or any(c.isspace() or c in ",/:#" for c in rule):
            raise BuildError(f"Invalid domain rule: {rule!r}")
        return rule.lower()
    if target_behavior == "ipcidr":
        try:
            return str(ipaddress.ip_network(rule, strict=False))
        except ValueError as error:
            raise BuildError(f"Invalid CIDR: {rule}") from error
    # Keep classical order, case, options and logical expressions intact.
    if "," not in rule:
        raise BuildError(f"Invalid classical rule: {rule!r}")
    return rule


def partition_rules(rules: list[str], partition: str) -> list[str]:
    """Split one classical source by exact domain-format representability."""
    if partition not in CLASSICAL_PARTITIONS:
        raise BuildError(f"Unknown source partition: {partition!r}")
    if partition == "domain-keyword":
        return [rule for rule in rules if rule.partition(",")[0].strip() == "DOMAIN-KEYWORD"]
    result = []
    for rule in rules:
        try:
            normalize_rule(rule, "classical", "domain")
            is_domain = True
        except BuildError:
            is_domain = False
        if is_domain == (partition == "domain"):
            result.append(rule)
    return result


def run_mihomo(binary: Path, args: list[str]) -> str:
    result = subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=180)
    output = result.stdout + result.stderr
    # Mihomo can log a skipped invalid rule and still exit successfully.
    if result.returncode or re.search(r"(?i)(level=(?:warn(?:ing)?|error|fatal)|skip invalid|invalid Ipcidr|parse classical rule .* error)", output):
        raise BuildError(f"Mihomo failed ({' '.join(args[:3])}):\n{output[-6000:]}")
    return output.strip()


def write_list(path: Path, rules: list[str]) -> None:
    path.write_text("\n".join(rules) + "\n", encoding="utf-8")


def compile_rules(binary: Path, behavior: str, rules: list[str], directory: Path, name: str) -> list[str]:
    """Export canonical text from MRS so all published formats describe one set."""
    list_path = directory / f"{name}.list"
    write_list(list_path, rules)
    if behavior == "classical":
        return rules
    mrs_path = directory / f"{name}.mrs"
    run_mihomo(binary, ["convert-ruleset", behavior, "text", str(list_path), str(mrs_path)])
    run_mihomo(binary, ["convert-ruleset", behavior, "mrs", str(mrs_path), str(list_path)])
    canonical = sorted(set(read_rules(list_path, "text")))
    write_list(list_path, canonical)
    # Re-encode canonical text and check a full round trip, including compact CIDRs.
    run_mihomo(binary, ["convert-ruleset", behavior, "text", str(list_path), str(mrs_path)])
    check = directory / f"{name}.roundtrip"
    run_mihomo(binary, ["convert-ruleset", behavior, "mrs", str(mrs_path), str(check)])
    if sorted(set(read_rules(check, "text"))) != canonical:
        raise BuildError(f"MRS round-trip mismatch: {name}")
    check.unlink()
    return canonical


def required_geodata(rules: list[str]) -> set[str]:
    databases = {"GEOSITE": "GeoSite.dat", "GEOIP": "Country.mmdb", "SRC-GEOIP": "Country.mmdb",
                 "IP-ASN": "ASN.mmdb", "SRC-IP-ASN": "ASN.mmdb"}
    required = set()
    for rule in rules:
        kind = rule.split(",", 1)[0].strip()
        if kind in databases:
            required.add(databases[kind])
        elif kind in ("AND", "OR", "NOT"):
            # Logical rules nest full rules inside parentheses. Limiting this
            # scan to logical expressions avoids matching ordinary regex text.
            for nested in re.findall(r"\(\s*(GEOSITE|GEOIP|SRC-GEOIP|IP-ASN|SRC-IP-ASN)\s*,", rule):
                required.add(databases[nested])
    return required


def validate_providers(binary: Path, output: Path, groups: dict, work: Path,
                       geodata_cache: Path, offline: bool = False) -> dict:
    providers = {}
    dependencies = set()
    for name, group in groups.items():
        format_ = "yaml" if group["behavior"] == "classical" else "mrs"
        if group["behavior"] == "classical":
            # File providers load lazily, so -t alone would miss invalid rules.
            providers[name] = {"type": "inline", "behavior": "classical",
                               "payload": read_rules(output / f"{name}.yaml", "yaml")}
            dependencies.update(required_geodata(providers[name]["payload"]))
        else:
            providers[name] = {"type": "file", "behavior": group["behavior"], "format": format_,
                               "path": str((output / f"{name}.{format_}").resolve())}
    if offline:
        for name in sorted(dependencies):
            cached = geodata_cache / name
            metadata_path = geodata_cache / f"{name}.json"
            if not cached.is_file() or not metadata_path.is_file():
                raise BuildError(f"No cached validation geodata: {name}; run an online build first")
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            except (ValueError, OSError) as error:
                raise BuildError(f"Invalid cached validation geodata metadata: {name}") from error
            if not isinstance(metadata, dict) or metadata.get("sha256") != sha256(cached):
                raise BuildError(f"Validation geodata cache hash mismatch: {name}")
            shutil.copyfile(cached, work / name)
    config = {"mode": "rule", "log-level": "info", "rule-providers": providers,
              "geodata-mode": False, "geo-auto-update": False,
              "rules": [f"RULE-SET,{name},DIRECT" for name in groups] + ["MATCH,DIRECT"]}
    if offline:
        # Even an unexpected native dependency must fail instead of making an
        # HTTP request. Mihomo's downloader rejects this unsupported URL scheme.
        config["geox-url"] = {kind: "offline://disabled" for kind in ("geoip", "geosite", "mmdb", "asn")}
    config_path = work / "validate.yaml"
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    run_mihomo(binary, ["-t", "-d", str(work.resolve()), "-f", str(config_path.resolve())])
    metadata = {}
    for name in sorted(dependencies):
        database = work / name
        if not database.is_file():
            raise BuildError(f"Missing validated geodata: {name}")
        metadata[name] = {"sha256": sha256(database), "bytes": database.stat().st_size}
    if metadata and not offline:
        geodata_cache.mkdir(parents=True, exist_ok=True)
        for name, entry in metadata.items():
            shutil.copyfile(work / name, geodata_cache / name)
            (geodata_cache / f"{name}.json").write_text(json.dumps(entry, indent=2) + "\n", encoding="utf-8")
    return metadata


def build(manifest: dict, binary: Path, output: Path, work: Path, offline: bool = False,
          source_root: Path = Path(".")) -> dict:
    ordered_rulesets = ruleset_order(manifest["rulesets"])
    binary = binary.resolve()
    if not binary.is_file():
        raise BuildError(f"Mihomo not found: {binary}; run scripts/install_mihomo.py")
    work.mkdir(parents=True, exist_ok=True)
    cache = work / "sources"
    if any("url" in source for source in manifest["sources"].values()):
        cache.mkdir(exist_ok=True)
    version = run_mihomo(binary, ["-v"])
    source_rules = {}
    source_meta = {}
    with tempfile.TemporaryDirectory(prefix="build-", dir=work) as temporary:
        temporary = Path(temporary).resolve()
        stage = temporary / "dist"
        stage.mkdir()

        def fetch(item):
            name, source = item
            cached = cache / f"{name}.{source['format']}"
            metadata_path = cache / f"{name}.json"
            fresh = temporary / f"{name}.source"
            is_local = "path" in source
            if is_local:
                # Snapshot current committed content even in offline mode; a
                # local edit must never be masked by yesterday's download cache.
                shutil.copyfile(local_source_path(source, source_root), fresh)
                metadata = {"path": source["path"], "sha256": sha256(fresh)}
            elif offline:
                if not cached.exists() or not metadata_path.exists():
                    raise BuildError(f"No cached source: {name}")
                metadata = json.loads(metadata_path.read_text())
                if metadata.get("url") != source["url"] or metadata.get("sha256") != sha256(cached):
                    raise BuildError(f"Cache provenance mismatch: {name}")
                shutil.copyfile(cached, fresh)
            else:
                download(source["url"], fresh)
                metadata = {"url": source["url"], "sha256": sha256(fresh),
                            "downloaded_at": datetime.now(timezone.utc).isoformat()}
            if source["format"] == "mrs":
                decoded = temporary / f"{name}.decoded"
                run_mihomo(binary, ["convert-ruleset", source["behavior"], "mrs", str(fresh), str(decoded)])
                rules = read_rules(decoded, "text")
            else:
                rules = read_rules(fresh, source["format"])
            input_count = len(rules)
            exclusions = set(source.get("exclude_rules", []))
            removed = [rule for rule in rules if rule in exclusions]
            rules = [rule for rule in rules if rule not in exclusions]
            if not rules:
                raise BuildError(f"Empty effective rule list after exclusions: {name}")
            partition_meta = {}
            if "partition" in source:
                count_before_partition = len(rules)
                rules = partition_rules(rules, source["partition"])
                if not rules:
                    raise BuildError(f"Empty effective rule list after partition: {name}")
                partition_meta = {"partition": source["partition"],
                                  "partitioned_out_rules_count": count_before_partition - len(rules)}
            if not is_local and not offline:
                shutil.copyfile(fresh, cached)
                metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")
            return name, rules, {**metadata, **partition_meta, "behavior": source["behavior"],
                                 "format": source["format"], "input_rules": input_count,
                                 "excluded_rules": removed, "excluded_rules_count": len(removed),
                                 "rules": len(rules)}

        with ThreadPoolExecutor(max_workers=6) as pool:
            for name, rules, metadata in pool.map(fetch, manifest["sources"].items()):
                source_rules[name] = rules
                source_meta[name] = metadata
                print(f"Source {name}: {len(rules)} rules", flush=True)

        result = {"version": 1, "built_at": datetime.now(timezone.utc).isoformat(),
                  "repository": manifest["repository"], "offline": offline, "mihomo": version,
                  "sources": source_meta, "rulesets": {}}
        providers = {}
        coverage_indexes = {}
        coverage_required = {dependency for group in manifest["rulesets"].values()
                             for dependency in group.get("exclude_covered_by", [])}
        for name in ordered_rulesets:
            group = manifest["rulesets"][name]
            combined = [normalize_rule(rule, manifest["sources"][source_id]["behavior"], group["behavior"])
                        for source_id in group["sources"] for rule in source_rules[source_id]]
            if group["behavior"] == "classical" and not manifest.get("allow_global_geodata", True):
                dependencies = required_geodata(combined)
                if dependencies:
                    raise BuildError(f"{name} requires global geodata: {', '.join(sorted(dependencies))}; "
                                     "use dedicated domain or ipcidr sources")
            unique = list(dict.fromkeys(combined))
            if group["behavior"] != "classical":
                unique.sort()
            compact = remove_internal_coverage(unique, group["behavior"])
            effective, covered_by = remove_covered_rules(compact, group["behavior"], {
                dependency: coverage_indexes[dependency] for dependency in group.get("exclude_covered_by", [])})
            if not effective:
                raise BuildError(f"Empty effective ruleset after coverage exclusions: {name}")
            canonical = compile_rules(binary, group["behavior"], effective, stage, name)
            if name in coverage_required:
                coverage_indexes[name] = RuleCoverage(group["behavior"], canonical)
            yaml_path = stage / f"{name}.yaml"
            # Mihomo's provider YAML reader consumes one payload entry per line.
            yaml_path.write_text(yaml.safe_dump({"payload": canonical}, allow_unicode=True,
                                                sort_keys=False, width=2**31 - 1), encoding="utf-8")
            formats = ["list", "yaml"] + ([] if group["behavior"] == "classical" else ["mrs"])
            result["rulesets"][name] = {"behavior": group["behavior"], "sources": group["sources"],
                "input_rules": len(combined), "unique_rules": len(unique), "rules": len(canonical),
                "exact_duplicates_removed": len(combined) - len(unique),
                "internally_covered_rules_removed": len(unique) - len(compact),
                "covered_rules_removed": len(compact) - len(effective), "covered_by": covered_by,
                "exclude_covered_by": group.get("exclude_covered_by", []),
                "files": {f"{name}.{ext}": {"sha256": sha256(stage / f"{name}.{ext}"),
                          "bytes": (stage / f"{name}.{ext}").stat().st_size} for ext in formats}}
            provider_format = "yaml" if group["behavior"] == "classical" else "mrs"
            providers[name] = {"type": "http", "behavior": group["behavior"], "format": provider_format,
                "interval": 86400, "path": f"./rule-sets/{name}.{provider_format}",
                "url": f"https://github.com/{manifest['repository']}/releases/latest/download/{name}.{provider_format}"}
            print(f"Ruleset {name}: {len(combined)} -> {len(unique)} unique -> {len(canonical)} canonical "
                  f"({len(unique) - len(compact)} internally covered, "
                  f"{len(compact) - len(effective)} covered by dependencies)", flush=True)

        result["validation_geodata"] = validate_providers(
            binary, stage, manifest["rulesets"], temporary, work / "geodata", offline=offline)
        (stage / "providers.yaml").write_text(yaml.safe_dump({"rule-providers": providers}, sort_keys=False), encoding="utf-8")
        if "mirror" in manifest:
            result["mirror_files"] = [Path(providers[name]["path"]).name for name in manifest["mirror"]]
        (stage / "manifest.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        notes = ["Daily Mihomo rules", "", "MRS, YAML and LIST built from public upstream and repository sources.",
                 "See manifest.json for source hashes, counts and build details.", "",
                 "| Ruleset | Behavior | Rules | Exact duplicates removed |", "| --- | --- | ---: | ---: |"]
        for name, group in result["rulesets"].items():
            notes.append(f"| {name} | {group['behavior']} | {group['rules']} | {group['exact_duplicates_removed']} |")
        (stage / "release-notes.md").write_text("\n".join(notes) + "\n", encoding="utf-8")
        checksums = [f"{sha256(path)}  {path.name}" for path in sorted(stage.iterdir())]
        (stage / "checksums.sha256").write_text("\n".join(checksums) + "\n", encoding="utf-8")
        output = output.resolve()
        # Only replace the previous successful build after all downloads and validation.
        output.parent.mkdir(parents=True, exist_ok=True)
        backup = temporary / "previous-dist"
        if output.exists():
            output.rename(backup)
        try:
            stage.rename(output)
        except OSError:
            if backup.exists():
                backup.rename(output)
            raise
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("rulesets.yaml"))
    parser.add_argument("--mihomo", type=Path, default=Path(".work/bin/mihomo"))
    parser.add_argument("--output", type=Path, default=Path("dist"))
    parser.add_argument("--work-dir", type=Path, default=Path(".work"))
    parser.add_argument("--offline", action="store_true", help="Rebuild from verified upstream cache and current repository sources")
    args = parser.parse_args()
    try:
        output = args.output.resolve()
        roots = {Path.cwd().resolve(), args.manifest.resolve().parent}
        protected = roots | {args.work_dir.resolve()}
        hidden_output = any(output != root and output.is_relative_to(root)
                            and output.relative_to(root).parts[0].startswith(".") for root in roots)
        if hidden_output or any(output == path or output in path.parents for path in protected):
            raise BuildError("Output must be a dedicated generated directory")
        result = build(load_manifest(args.manifest), args.mihomo, args.output, args.work_dir,
                       args.offline, source_root=args.manifest.parent)
    except (BuildError, OSError, yaml.YAMLError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Build failed: {error}\n")
    print(f"Built {len(result['rulesets'])} rulesets in {args.output}")


if __name__ == "__main__":
    main()
