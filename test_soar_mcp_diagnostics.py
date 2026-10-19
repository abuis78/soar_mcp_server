"""Tests for the diagnostics tool (issue #67)."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from soar_mcp_config import READ_ONLY_TOOLS, McpServerConfig
from soar_mcp_tokens import TokenStore
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


class PrincipalCountsTest(unittest.TestCase):
    """SPEC-MCP MCP-G06: diagnostics report active tokens per principal_type."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        TokenStore._instances.clear()
        self.store = TokenStore.for_path(Path(self._tmp.name) / "mcp_tokens.json")
        self._orig_default = TokenStore.default
        TokenStore.default = classmethod(lambda cls, s=self.store: s)

    def tearDown(self) -> None:
        TokenStore.default = self._orig_default
        TokenStore._instances.clear()
        self._tmp.cleanup()

    def _diag(self, cfg):
        out = call_tool("diagnose_soar_mcp_environment", {"output_format": "json"},
                        _FakeClient(), cfg)
        return json.loads(out), out

    def test_counts_mixed_store(self):
        m = self.store.mint(label="h1", soar_user_id="h", soar_call_token="ph_h1")
        self.store.mint(label="h2", soar_user_id="h", soar_call_token="ph_h2")
        self.store.mint(label="a1", soar_user_id="svc", soar_call_token="ph_a1",
                        principal_type="agent", agent_id="triage")
        self.store.mint(label="b1", soar_user_id="svc", soar_call_token="ph_b1",
                        principal_type="broker")
        self.store.revoke(m.id)                       # revoked -> not counted
        cfg = _cfg(); cfg.scoped_tokens_enabled = True
        d, raw = self._diag(cfg)
        self.assertEqual(d["data"]["principal_counts"],
                         {"agent": 1, "broker": 1, "mensch": 1})
        for leak in ("h1", "h2", "a1", "b1", "ph_", "tok_", "triage"):
            self.assertNotIn(leak, raw)

    def test_null_when_scoped_tokens_disabled(self):
        self.store.mint(label="h1", soar_user_id="h", soar_call_token="ph_h1")
        cfg = _cfg(); cfg.scoped_tokens_enabled = False
        d, _ = self._diag(cfg)
        self.assertIsNone(d["data"]["principal_counts"])

    def test_unreadable_store_is_warning_not_crash(self):
        def boom(cls):
            raise RuntimeError("store broken")
        TokenStore.default = classmethod(boom)
        cfg = _cfg(); cfg.scoped_tokens_enabled = True
        d, _ = self._diag(cfg)
        self.assertIsNone(d["data"]["principal_counts"])
        self.assertTrue(any(f.get("code") == "token_store_unreadable" for f in d["findings"]))
        self.assertTrue(d["ok"])   # warn, not error

    def test_agent_read_exceptions_flagged_in_posture(self):
        cfg = _cfg(); cfg.agent_read_exceptions = ["get_soar_info"]
        d, _ = self._diag(cfg)
        self.assertEqual(d["data"]["security_posture"]["agent_read_exceptions"], ["get_soar_info"])
        self.assertIn("agent_read_exceptions_set", d["data"]["security_posture"]["risk_flags"])
        d2, _ = self._diag(_cfg())
        self.assertNotIn("agent_read_exceptions_set", d2["data"]["security_posture"]["risk_flags"])


if __name__ == "__main__":
    unittest.main()
