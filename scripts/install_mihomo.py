#!/usr/bin/env python3
"""Install the pinned official Mihomo binary for Linux x86-64 into .work."""

from __future__ import annotations

import argparse
import gzip
import hashlib
from http.client import HTTPException
import os
from pathlib import Path
import platform
import shutil
import sys
import tempfile
import time
from urllib.error import URLError
from urllib.request import Request, urlopen


VERSION = "v1.19.33"
ARCHIVE_NAME = f"mihomo-linux-amd64-compatible-{VERSION}.gz"
URL = f"https://github.com/MetaCubeX/mihomo/releases/download/{VERSION}/{ARCHIVE_NAME}"
SHA256 = "386508bfb1c72c43b6a0eda73708ecdce82546581b0ebcb16366c53757c622b6"
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / ".work" / "bin" / "mihomo"
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024


def download_verified(destination: Path, attempts: int = 4) -> None:
    """Retry transient failures, and never accept an unverified archive."""
    for attempt in range(1, attempts + 1):
        try:
            digest = hashlib.sha256()
            size = 0
            request = Request(URL, headers={"User-Agent": "mihomo-rules-installer"})
            with urlopen(request, timeout=60) as response, destination.open("wb") as output:
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > MAX_ARCHIVE_BYTES:
                        raise ValueError("Mihomo archive exceeds the download size limit")
                    digest.update(chunk)
                    output.write(chunk)
            actual = digest.hexdigest()
            if actual != SHA256:
                raise ValueError(f"Mihomo SHA-256 mismatch: expected {SHA256}, received {actual}")
            return
        except (OSError, URLError, HTTPException, ValueError) as error:
            destination.unlink(missing_ok=True)
            if attempt == attempts:
                raise RuntimeError(f"Could not download verified Mihomo {VERSION}: {error}") from error
            print(f"Download attempt {attempt}/{attempts} failed: {error}; retrying", file=sys.stderr)
            time.sleep(2 ** attempt)


def install(destination: Path) -> None:
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise RuntimeError(
            "This installer supports Linux x86-64 (including WSL). "
            "On another platform, install Mihomo yourself and pass --mihomo to scripts/build.py."
        )
    destination = destination.absolute()
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Keep temporary downloads on the destination filesystem so os.replace is atomic.
    with tempfile.TemporaryDirectory(prefix=".mihomo-install-", dir=destination.parent) as temporary:
        archive = Path(temporary) / ARCHIVE_NAME
        binary = Path(temporary) / "mihomo"
        download_verified(archive)
        with gzip.open(archive, "rb") as source, binary.open("wb") as output:
            shutil.copyfileobj(source, output)
            output.flush()
            os.fsync(output.fileno())
        binary.chmod(0o755)
        os.replace(binary, destination)
    print(f"Installed Mihomo {VERSION}: {destination}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="binary path (default: .work/bin/mihomo)")
    arguments = parser.parse_args()
    try:
        install(arguments.output)
    except (OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
