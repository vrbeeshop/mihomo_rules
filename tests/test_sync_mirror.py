from contextlib import redirect_stdout
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import sync_mirror as mirror


class MirrorTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.site = Path(temporary.name)
        self.payloads = {"domains.mrs": b"domain rules", "extra.yaml": b"extra rules"}
        self.requests = []

    def release(self, names):
        manifest = {"mirror_files": names, "rulesets": {
            Path(n).stem: {"files": {n: {}}} for n in names}}
        self.payloads["manifest.json"] = json.dumps(manifest).encode()
        self.payloads["checksums.sha256"] = "".join(
            f"{sha256(data).hexdigest()}  {name}\n" for name, data in self.payloads.items()
        ).encode()
        self.payloads["latest"] = json.dumps({"tag_name": "r1", "assets": [{
            "name": "checksums.sha256", "digest": "sha256:" + sha256(self.payloads["checksums.sha256"]).hexdigest()
        }]}).encode()

    def sync(self):
        def fetch(url):
            name = url.rsplit("/", 1)[1]
            if name != "latest":
                self.assertIn("/releases/download/r1/", url)
            self.requests.append(name)
            return self.payloads[name]
        with patch.object(mirror, "fetch", side_effect=fetch), redirect_stdout(StringIO()):
            mirror.sync(self.site)

    def test_first_sync_unchanged_release_and_repair(self):
        homepage = self.site / "index.html"
        homepage.write_text("existing site")
        self.release(list(self.payloads))
        self.sync()
        self.assertEqual((self.site / "domains.mrs").read_bytes(), b"domain rules")
        self.assertEqual((self.site / "extra.yaml").stat().st_mode & 0o777, 0o644)
        self.requests.clear()
        self.sync()
        self.assertEqual(self.requests, ["latest", "checksums.sha256", "manifest.json"])
        for corrupt in (False, True):
            if corrupt:
                (self.site / "extra.yaml").write_bytes(b"damaged")
            else:
                (self.site / "extra.yaml").unlink()
            self.requests.clear()
            self.sync()
            self.assertNotIn("domains.mrs", self.requests)
            self.assertEqual((self.site / "extra.yaml").read_bytes(), b"extra rules")
        self.assertEqual(homepage.read_text(), "existing site")

    def test_bad_hash_preserves_all_previous_files(self):
        self.release(list(self.payloads))
        for name in ("domains.mrs", "extra.yaml"):
            (self.site / name).write_bytes(b"previous")
        self.payloads["extra.yaml"] = b"bad transfer"
        with self.assertRaisesRegex(ValueError, "SHA256 mismatch for extra.yaml"):
            self.sync()
        self.assertEqual(sorted(p.name for p in self.site.iterdir()), ["domains.mrs", "extra.yaml"])
        self.assertTrue(all(p.read_bytes() == b"previous" for p in self.site.iterdir()))

    def test_rejects_non_rule_paths_and_existing_symlink(self):
        self.release(["../home.yaml"])
        with self.assertRaisesRegex(ValueError, "Invalid mirror filename"):
            self.sync()
        self.payloads = {"domains.mrs": b"new content"}
        self.release(["domains.mrs"])
        homepage = self.site / "index.html"
        homepage.write_text("keep")
        (self.site / "domains.mrs").symlink_to(homepage)
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.sync()
        self.assertEqual(homepage.read_text(), "keep")

    def test_permission_failure_during_replacement_rolls_back_existing_and_new_files(self):
        self.payloads["last.mrs"] = b"last file"
        self.release(list(self.payloads))
        (self.site / "domains.mrs").write_bytes(b"previous domains")
        (self.site / "last.mrs").write_bytes(b"existing rules")
        replace = Path.replace

        def fail_last(source, target):
            if source.name == "last.mrs":
                raise PermissionError("sticky directory")
            return replace(source, target)

        with patch.object(Path, "replace", fail_last), self.assertRaises(PermissionError):
            self.sync()
        self.assertEqual((self.site / "domains.mrs").read_bytes(), b"previous domains")
        self.assertEqual((self.site / "last.mrs").read_bytes(), b"existing rules")
        self.assertFalse((self.site / "extra.yaml").exists())
