"""Tests for the SOAR app package hygiene linter (issue #71)."""
from __future__ import annotations

import io
import json
import os
import tarfile
import tempfile
import unittest

from scripts.lint_soar_app_package import lint_archive

_TOP = "soar_mcp_server"
_REQUIRED = [
    "soar_mcp_server.json",
    "soar_mcp_connector.py",
    "soar_mcp_handler.py",
    "soar_mcp_config.py",
    "soar_mcp_tools.py",
]
_GOOD_MANIFEST = json.dumps({
    "appid": "ff5f68f3", "app_version": "1.8.0",
    "main_module": "soar_mcp_connector.py", "rest_handler": "soar_mcp_handler.X",
}).encode()


def _build(members: dict[str, bytes], *, add_topdir: bool = True,
           extra: list[tarfile.TarInfo] | None = None) -> str:
    """Write a tar.gz to a temp file and return its path."""
    fd, path = tempfile.mkstemp(suffix=".tar.gz")
    os.close(fd)
    with tarfile.open(path, "w:gz") as tf:
        if add_topdir:
            d = tarfile.TarInfo(f"{_TOP}/")
            d.type = tarfile.DIRTYPE
            tf.addfile(d)
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        for info in (extra or []):
            tf.addfile(info)
    return path


def _clean_members() -> dict[str, bytes]:
    m = {f"{_TOP}/{f}": (b"x" if not f.endswith(".json") else _GOOD_MANIFEST)
         for f in _REQUIRED}
    return m


class PackageLinterTest(unittest.TestCase):
    def tearDown(self):
        for p in getattr(self, "_paths", []):
            try:
                os.unlink(p)
            except OSError:
                pass

    def _lint(self, members, **kw):
        path = _build(members, **kw)
        self._paths = getattr(self, "_paths", []) + [path]
        return lint_archive(path)

    def test_clean_package_passes(self):
        r = self._lint(_clean_members())
        self.assertTrue(r["ok"], r["errors"])

    def test_ds_store_blocked(self):
        m = _clean_members()
        m[f"{_TOP}/.DS_Store"] = b"junk"
        r = self._lint(m)
        self.assertFalse(r["ok"])
        self.assertTrue(any(".DS_Store" in e for e in r["errors"]))

    def test_apple_dotbar_blocked(self):
        m = _clean_members()
        m[f"{_TOP}/._soar_mcp_tools.py"] = b"junk"
        r = self._lint(m)
        self.assertFalse(r["ok"])

    def test_missing_topdir_flagged(self):
        r = self._lint(_clean_members(), add_topdir=False)
        self.assertFalse(r["ok"])
        self.assertTrue(any("top-level directory" in e for e in r["errors"]))

    def test_missing_manifest_flagged(self):
        m = _clean_members()
        del m[f"{_TOP}/soar_mcp_server.json"]
        r = self._lint(m)
        self.assertFalse(r["ok"])
        self.assertTrue(any("soar_mcp_server.json" in e for e in r["errors"]))

    def test_invalid_manifest_json_flagged(self):
        m = _clean_members()
        m[f"{_TOP}/soar_mcp_server.json"] = b"{not valid json"
        r = self._lint(m)
        self.assertFalse(r["ok"])

    def test_releases_artifact_excluded(self):
        m = _clean_members()
        m[f"{_TOP}/releases/app_v1.tar"] = b"x"
        r = self._lint(m)
        self.assertFalse(r["ok"])
        self.assertTrue(any("release/local artifact" in e for e in r["errors"]))

    def test_path_traversal_blocked(self):
        extra = tarfile.TarInfo(f"{_TOP}/../evil.py")
        extra.size = 0
        r = self._lint(_clean_members(), extra=[extra])
        self.assertFalse(r["ok"])
        self.assertTrue(any("traversal" in e for e in r["errors"]))


if __name__ == "__main__":
    unittest.main()
