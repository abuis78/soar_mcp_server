"""Tests for the visual playbook pre-edit audit (issue #69)."""
from __future__ import annotations

import json
import unittest

from soar_mcp_config import READ_ONLY_TOOLS, McpServerConfig
from soar_mcp_tools import call_tool


class _HealthyClient:
    """Mimics verified 8.5.0.248 shapes for a clean playbook."""
    def _coa_get(self, path, params=None):
        return {
            "id": 1, "current_id": 1, "name": "AD_LDAP_Account_Locking",
            "playbook_trigger": "artifact_created", "playbook_type": "data",
            "passed_validation": True, "node_count": 6,
            "coa_data": {"nodes": {str(i): {"data": {"functionName": f"n{i}"}} for i in range(6)},
                         "edges": [{"source": "0", "target": "1"}]},
        }, None

    def get(self, path, params=None):
        if path.startswith("playbook/"):
            return {"id": 1, "passed_validation": True,
                    "python": "def on_start(c):\n    pass\n"}, None
        if path == "playbook":
            return {"data": [{"id": 1}]}, None
        return {}, None

    def get_binary(self, path, params=None):
        return b"TAR", None


class _UnreachableClient:
    """COA + export both unavailable → verdict must be 'unknown', not 'pass'."""
    def _coa_get(self, path, params=None):
        return None, "Connection error: could not reach COA endpoint."
    def get(self, path, params=None):
        if path == "playbook":
            return {"data": [{"id": 1}]}, None
        return None, "Connection error: could not reach SOAR REST API."
    def get_binary(self, path, params=None):
        return None, "Connection error."


def _cfg():
    c = McpServerConfig()
    c.enabled_tools = set(READ_ONLY_TOOLS)
    c.advisory_disclaimer = False
    return c


class AuditTest(unittest.TestCase):
    def test_registered_read_only(self):
        from soar_mcp_tools import TOOL_SCHEMAS, _TOOL_HANDLERS
        self.assertIn("audit_visual_playbook", TOOL_SCHEMAS)
        self.assertIn("audit_visual_playbook", _TOOL_HANDLERS)
        self.assertIn("audit_visual_playbook", READ_ONLY_TOOLS)

    def test_healthy_playbook_passes(self):
        out = call_tool("audit_visual_playbook",
                        {"playbook_id": 1, "output_format": "json"}, _HealthyClient(), _cfg())
        d = json.loads(out)
        self.assertIn(d["data"]["verdict"], ("pass", "warn"))
        self.assertEqual(d["data"]["node_count"], 6)
        self.assertTrue(d["data"]["capabilities"]["coa_graph_extractable"])
        self.assertTrue(d["data"]["recommendations"])

    def test_unreachable_is_unknown_not_pass(self):
        out = call_tool("audit_visual_playbook",
                        {"playbook_id": 1, "output_format": "json"}, _UnreachableClient(), _cfg())
        d = json.loads(out)
        self.assertEqual(d["data"]["verdict"], "unknown")
        self.assertFalse(d["ok"])
        self.assertTrue(any("cannot audit" in r for r in d["data"]["recommendations"]))

    def test_never_claims_safe_when_python_unknown(self):
        client = _HealthyClient()
        client.get_binary = lambda p, params=None: (None, "404")
        client.get = lambda p, params=None: (
            ({"data": [{"id": 1}]}, None) if p == "playbook"
            else ({"id": 1, "passed_validation": True}, None)  # no python field
        )
        out = call_tool("audit_visual_playbook",
                        {"playbook_id": 1, "output_format": "json"}, client, _cfg())
        d = json.loads(out)
        # python unknown → at least 'warn', never a clean 'pass'
        self.assertIn(d["data"]["verdict"], ("warn", "unknown", "fail"))


if __name__ == "__main__":
    unittest.main()
