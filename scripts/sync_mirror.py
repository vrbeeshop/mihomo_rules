"""Sync published client rules into an existing web root. Uses only the Python standard library."""

import argparse
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
from urllib.request import Request, urlopen


REPO = "vrbeeshop/mihomo_rules"


def fetch(url):
    request = Request(url, headers={"User-Agent": "mihomo-rules-mirror"})
    with urlopen(request, timeout=45) as response:
        if not response.geturl().startswith("https://"):
            raise ValueError("Insecure download redirect")
        data = response.read(128 * 1024 * 1024 + 1)
        if len(data) > 128 * 1024 * 1024:
            raise ValueError("Download exceeds size limit")
        return data


def verified_asset(base, name, digests):
    data = fetch(f"{base}/{name}")
    if sha256(data).hexdigest() != digests[name]:
        raise ValueError(f"SHA256 mismatch for {name}")
    return data


def sync(site):
    # Lock the directory itself so manual runs and systemd cannot interleave.
    directory = os.open(site, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(directory, fcntl.LOCK_EX)
        return sync_latest(site)
    finally:
        os.close(directory)


def sync_latest(site):
    release = json.loads(fetch(f"https://api.github.com/repos/{REPO}/releases/latest"))
    tag = release["tag_name"]
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]*", tag):
        raise ValueError("Invalid release tag")
    # Pin every request to this release even if 'latest' changes mid-download.
    base = f"https://github.com/{REPO}/releases/download/{tag}"
    checksum_asset = next((a for a in release["assets"] if a["name"] == "checksums.sha256"), None)
    checksums = fetch(f"{base}/checksums.sha256")
    if not checksum_asset or checksum_asset["digest"] != "sha256:" + sha256(checksums).hexdigest():
        raise ValueError("SHA256 mismatch for release checksums")
    digests = {}
    for line in checksums.decode("utf-8").splitlines():
        digest, name = line.split("  ", 1)
        if not re.fullmatch(r"[a-f0-9]{64}", digest) or name in digests:
            raise ValueError("Invalid release checksums")
        digests[name] = digest
    manifest = json.loads(verified_asset(base, "manifest.json", digests))
    files = manifest["mirror_files"]
    if not isinstance(files, list) or not files:
        raise ValueError("Missing mirror file list")
    pending = []
    for name in files:
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]*\.(mrs|yaml)", name):
            raise ValueError("Invalid mirror filename")
        if name not in digests or name not in manifest["rulesets"][Path(name).stem]["files"]:
            raise ValueError(f"Missing release file: {name}")
        target = site / name
        try:
            info = target.lstat()
        except FileNotFoundError:
            pending.append(name)
            continue
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"Expected a regular file: {target}")
        if sha256(target.read_bytes()).hexdigest() != digests[name]:
            pending.append(name)
    if len(set(files)) != len(files):
        raise ValueError("Duplicate mirror filenames")
    if pending:
        with tempfile.TemporaryDirectory(prefix=".mirror-", dir=site) as tmp:
            stage = Path(tmp)
            for name in pending:
                path = stage / name
                path.write_bytes(verified_asset(base, name, digests))
                path.chmod(0o644)
            previous = stage / "previous"
            previous.mkdir()
            installed = []
            try:
                for name in pending:
                    target = site / name
                    if target.exists():
                        shutil.copy2(target, previous / name)
                    (stage / name).replace(target)
                    installed.append(name)
            except OSError:
                for name in reversed(installed):
                    if (previous / name).exists():
                        (previous / name).replace(site / name)
                    else:
                        (site / name).unlink()
                raise
    print(f"{tag}: {len(files)} rulesets verified, {len(pending)} updated", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("site", type=Path, help="Existing directory served by the web server")
    try:
        sync(parser.parse_args().site)
    except (ValueError, OSError, KeyError) as error:
        sys.exit(f"Mirror sync failed: {error}")
