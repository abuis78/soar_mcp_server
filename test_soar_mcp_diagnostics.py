"""Tests for the diagnostics tool (issue #67)."""
from __future__ import annotations

import json
import unittest

from soar_mcp_config import READ_ONLY_TOOLS, McpServerConfig
from soar_mcp_tools import call_tool


class _FakeClient:
    def __init__(self, auth="tok", version="6.3.0", fail=False, base_url="https://s/rest"):
        self._auth_token = auth
        self._version = version
        self._fail = fail
        self._base_url = base_url

    def get(self, path, params=None):
        if path == "version" and not self._fail:
            return {"version": self._version}, None
        return None, "Connection error: could not reach SOAR REST API."


def _cfg():
    c = McpServerConfig()
    c.mcp_endpoint = "https://soar.x/rest/handler/soarmcpserver_a/mcp"
    c.enabled_tools = set(READ_ONLY_TOOLS)
    return c


class DiagnosticsTest(unittest.TestCase):
    def test_healthy_environment_ok(self):
        out = call_tool("diagnose_soar_mcp_environment", {"output_format": "json"},
                        _FakeClient(), _cfg())
        d = json.loads(out)
        self.assertTrue(d["ok"], d)
        self.assertTrue(d["data"]["handler_reachable"])
        self.assertEqual(d["data"]["soar_version"], "6.3.0")

    def test_unreachable_marks_not_ok(self):
        out = call_tool("diagnose_soar_mcp_environment", {"output_format": "json"},
                        _FakeClient(fail=True), _cfg())
        d = json.loads(out)
        self.assertFalse(d["ok"])
        self.assertFalse(d["data"]["handler_reachable"])

    def test_never_leaks_token(self):
        out = call_tool("diagnose_soar_mcp_environment", {},
                        _FakeClient(auth="SUPER-SECRET"), _cfg())
        self.assertNotIn("SUPER-SECRET", out)

    def test_missing_token_is_error_finding(self):
        out = call_tool("diagnose_soar_mcp_environment", {"output_format": "json"},
                        _FakeClient(auth=""), _cfg())
        d = json.loads(out)
        self.assertFalse(d["ok"])
        self.assertTrue(any(f.get("code") == "no_auth_token" for f in d["findings"]))

    def test_missing_base_url_is_reported(self):
        # #122: after an upgrade wipes local/, base_url can be empty. Diagnose
        # must still run and surface a base_url_unresolved finding.
        out = call_tool("diagnose_soar_mcp_environment", {"output_format": "json"},
                        _FakeClient(base_url="", fail=True), _cfg())
        d = json.loads(out)
        self.assertFalse(d["ok"])
        self.assertTrue(any(f.get("code") == "base_url_unresolved" for f in d["findings"]))


if __name__ == "__main__":
    unittest.main()
