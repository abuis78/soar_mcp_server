"""Regression coverage for SOAR 8.5 validation and Python drift checks."""
from __future__ import annotations

import io
import json
import tarfile
import unittest

from soar_mcp_config import McpServerConfig
from soar_mcp_tools import (
    tool_check_saved_generated_python_drift,
    tool_validate_playbook_bundle,
)


def _tar_with_python(source: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tarf:
        payload = source.encode("utf-8")
        info = tarfile.TarInfo("playbook.py")
        info.size = len(payload)
        tarf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


class _FakeValidationClient:
    def __init__(self) -> None:
        self.coa = {
            "id": 180,
            "current_id": 180,
            "coa_data": {
                "nodes": {
                    "0": {
                        "id": "0",
                        "data": {"type": "code", "functionName": "do_work"},
                    }
                },
                "edges": [],
            },
            "python": (
                "def on_start(container):\n"
                "    do_work(container)\n\n"
                "def do_work(container):\n"
                "    return None\n\n"
                "def on_finish(container, summary):\n"
                "    return None\n"
            ),
        }

    def get(self, path, params=None):
        if path == "playbook/180":
            return {
                "id": 180,
                "name": "Quarantine",
                "version": 9,
                "passed_validation": True,
            }, None
        if path == "playbook/180/validate":
            raise AssertionError("SOAR 8.5 validate endpoint must not be called")
        return {}, None

    def _coa_get(self, path, params=None):
        return self.coa, None

    def get_binary(self, path, params=None):
        return _tar_with_python(self.coa["python"]), None


class Soar85ValidationDriftTest(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = McpServerConfig()
        self.cfg.advisory_disclaimer = False
        self.client = _FakeValidationClient()

    def test_validate_bundle_does_not_probe_validate_endpoint(self):
        data = json.loads(tool_validate_playbook_bundle(self.client, self.cfg, {"playbook_id": 180}))
        names = [c["name"] for c in data["data"]["checks"]]
        self.assertNotIn("validate_structure", names)
        self.assertEqual(data["ok"], True)

    def test_drift_check_uses_coa_python_payload(self):
        data = json.loads(tool_check_saved_generated_python_drift(self.client, self.cfg, {"playbook_id": 180}))
        self.assertEqual(data["data"]["status"], "completed")
        self.assertEqual(data["data"]["python_source"], "coa_python")
        self.assertEqual(data["ok"], True)


if __name__ == "__main__":
    unittest.main()
