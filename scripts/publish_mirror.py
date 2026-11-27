"""Publish the client rule files from the already verified dist/ artifact over SFTP."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


FILE_LIST = Path(__file__).resolve().parents[1] / ".github" / "mirror-files.txt"


def publish():
    dist = Path("dist")
    rulesets = json.loads((dist / "manifest.json").read_text())["rulesets"]
    files = FILE_LIST.read_text().splitlines()
    if not files or len(files) != len(set(files)):
        sys.exit("Empty mirror file list or duplicate entries")
    for name in files:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*\.(mrs|yaml)", name):
            sys.exit("Invalid mirror filename")
        group = rulesets.get(Path(name).stem, {})
        if name not in group.get("files", {}) or not (dist / name).is_file() or (dist / name).is_symlink():
            sys.exit(f"Missing verified ruleset: {name}")

    host = os.environ.get("MIRROR_HOST", "")
    user = os.environ.get("MIRROR_USER", "rules-publisher")
    port = os.environ.get("MIRROR_PORT", "22")
    directory = os.environ.get("MIRROR_DIR", "")
    host_key = os.environ.get("MIRROR_HOST_KEY", "").strip()
    private_key = os.environ.get("MIRROR_PRIVATE_KEY", "").strip()
    if not re.fullmatch(r"[a-zA-Z0-9_.:-]+", host) or not re.fullmatch(r"[a-zA-Z0-9_.-]+", user):
        sys.exit("Check MIRROR_HOST and MIRROR_USER")
    if not re.fullmatch(r"[0-9]{1,5}", port) or not 1 <= int(port) <= 65535:
        sys.exit("Invalid MIRROR_PORT")
    if not directory.startswith("/") or any(not c.isprintable() for c in directory):
        sys.exit("MIRROR_DIR must be an absolute SFTP directory on one line")
    if not private_key or not re.fullmatch(r"[\w@.-]+ [A-Za-z0-9+/]+={0,2}", host_key):
        sys.exit("Set MIRROR_PRIVATE_KEY and MIRROR_HOST_KEY (key type and base64 data)")

    # SFTP batch mode uses its own double-quoted argument syntax.
    quoted = directory.replace("\\", "\\\\").replace('"', '\\"')
    batch = [f'cd "{quoted}"']
    batch.extend(f"put {name} .{name}.incoming" for name in files)
    batch.extend(f"rename .{name}.incoming {name}" for name in files)
    with tempfile.TemporaryDirectory(prefix="mirror-") as temp:
        identity = Path(temp) / "identity"
        identity.touch(mode=0o600)
        identity.write_text(private_key.replace("\r\n", "\n") + "\n")
        known_hosts = Path(temp) / "known_hosts"
        known_hosts.write_text("rules-mirror " + host_key + "\n")
        # SFTP echoes batch commands and SSH errors may include the endpoint.
        # Only a fixed diagnostic is sent to the Actions log on failure.
        result = subprocess.run([
            "sftp", "-F", "/dev/null", "-b", "-", "-i", str(identity), "-P", port,
            "-o", f"Hostname={host}", "-o", f"User={user}", "-o", "HostKeyAlias=rules-mirror",
            "-o", f"UserKnownHostsFile={known_hosts}", "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
            "-o", "ConnectTimeout=20", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
            "rules-mirror",
        ], cwd=dist, input="\n".join(batch) + "\n", text=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if result.returncode:
        if "Host key verification failed" in result.stderr:
            sys.exit("SFTP host key verification failed. Check the server key using its console.")
        if "Permission denied (publickey" in result.stderr:
            sys.exit("SFTP authentication failed. Check the deploy key and account.")
        sys.exit("SFTP upload failed. Check connectivity, destination directory and write/rename permissions.")
    print(f"Published {len(files)} rule files via SFTP")


if __name__ == "__main__":
    publish()
