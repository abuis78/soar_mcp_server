"""SPEC-MCP MCP-L01/L02: agent-principal tokens get no direct read tools.

Phase 1.4 covers tools/list visibility; 1.5 adds the tools/call rejection.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from soar_mcp_config import ALL_TOOLS, READ_ONLY_TOOLS, McpServerConfig
from soar_mcp_handler import SoarMcpRestHandler
from soar_mcp_tokens import TokenVerification


def _handler():
    # Bypass __init__ (full request processing) — only one method under test.
    return SoarMcpRestHandler.__new__(SoarMcpRestHandler)


def _tv(principal_type="mensch", agent_id=None, allowed_tools=None):
    return TokenVerification(valid=True, token_id="tok_x", label="t", soar_user_id="u",
                             soar_call_token="ph", allowed_tools=allowed_tools,
                             principal_type=principal_type, agent_id=agent_id)


def _cfg(exceptions=None):
    cfg = McpServerConfig()
    cfg.enabled_tools = set(ALL_TOOLS)          # everything on, to see the gate alone
    cfg.agent_read_exceptions = list(exceptions or [])
    return cfg


def _names(cfg, tv):
    return {t["name"] for t in _handler()._handle_tools_list(cfg, tv)["tools"]}


class AgentReadGateListTest(unittest.TestCase):
    def test_agent_sees_no_read_tools(self):
        names = _names(_cfg(), _tv("agent", "a1"))
        self.assertFalse(names & READ_ONLY_TOOLS, names & READ_ONLY_TOOLS)

    def test_agent_still_sees_enabled_write_tools(self):
        names = _names(_cfg(), _tv("agent", "a1"))
        self.assertIn("add_case_note", names)
        self.assertIn("run_playbook", names)

    def test_agent_sees_exceptions_only(self):
        names = _names(_cfg(["get_soar_info"]), _tv("agent", "a1"))
        self.assertEqual(names & READ_ONLY_TOOLS, {"get_soar_info"})

    def test_agent_exception_still_subject_to_allowed_tools(self):
        tv = _tv("agent", "a1", allowed_tools=["add_case_note"])
        names = _names(_cfg(["get_soar_info"]), tv)
        self.assertEqual(names, {"add_case_note"})

    def test_human_unchanged(self):
        cfg = _cfg(["get_soar_info"])
        self.assertEqual(_names(cfg, _tv("mensch")), _names(cfg, None))
        self.assertTrue(READ_ONLY_TOOLS <= _names(cfg, _tv("mensch")))

    def test_broker_sees_read_tools_only(self):
        """Phase 3.4 hid approve_action; Phase 4.1 (MCP-L05, OQ-14) hides every write tool."""
        cfg = _cfg()
        names = _names(cfg, _tv("broker"))
        self.assertEqual(names, _names(cfg, None) & READ_ONLY_TOOLS)
        self.assertTrue(names)  # reads stay visible

    def test_broker_allow_list_cannot_add_write_tools(self):
        cfg = _cfg()
        tv = _tv("broker", allowed_tools=["get_case", "run_playbook", "approve_action"])
        self.assertEqual(_names(cfg, tv), {"get_case"})

    def test_broker_write_call_refused_even_when_listed(self):
        """AC-07: a broker token can read but never write."""
        cfg = _cfg()
        h = _handler()
        tv = _tv("broker", allowed_tools=["get_case", "run_playbook", "approve_action"])
        for tool in ("run_playbook", "approve_action"):  # both on the allow-list, still refused
            with patch("soar_mcp_handler.call_tool") as ct, \
                    patch.object(SoarMcpRestHandler, "_audit_tool_call") as audit:
                res = h._handle_tools_call({"name": tool, "arguments": {"case_id": 1}}, object(), cfg, tv)
            self.assertTrue(res.get("isError"), tool)
            self.assertIn("read tool", res["content"][0]["text"])
            ct.assert_not_called()
            self.assertEqual(audit.call_args.kwargs.get("outcome"), "denied:broker_write")
        with patch("soar_mcp_handler.call_tool", return_value="ok") as ct, \
                patch.object(SoarMcpRestHandler, "_audit_tool_call"):
            res = h._handle_tools_call({"name": "get_case", "arguments": {"case_id": 1}}, object(), cfg, tv)
        self.assertFalse(res.get("isError"))
        ct.assert_called_once()

    def test_legacy_token_unchanged(self):
        cfg = _cfg()
        expected = (set(ALL_TOOLS) - SoarMcpRestHandler._HIDDEN_FROM_LIST)
        self.assertEqual(_names(cfg, None), expected)

    def test_hidden_from_list_still_applies_for_agent(self):
        names = _names(_cfg(), _tv("agent", "a1"))
        self.assertNotIn("save_playbook_layout_only", names)

    def test_helper_truth_table(self):
        h = SoarMcpRestHandler._agent_read_blocked
        cfg = _cfg(["get_soar_info"])
        self.assertTrue(h("get_case", cfg, _tv("agent", "a1")))
        self.assertFalse(h("get_soar_info", cfg, _tv("agent", "a1")))   # exception
        self.assertFalse(h("add_case_note", cfg, _tv("agent", "a1")))  # write tool
        self.assertFalse(h("get_case", cfg, _tv("mensch")))
        self.assertFalse(h("get_case", cfg, _tv("broker")))
        self.assertFalse(h("get_case", cfg, None))


class _FakeClient:
    pass


def _call(cfg, tv, tool, arguments=None):
    """Run _handle_tools_call with call_tool mocked; return (result, call_tool_mock)."""
    with patch("soar_mcp_handler.call_tool", return_value="fine") as ct:
        result = _handler()._handle_tools_call(
            {"name": tool, "arguments": arguments or {}}, _FakeClient(), cfg, tv)
    return result, ct


class AgentReadGateCallTest(unittest.TestCase):
    def test_agent_rejected_on_every_read_tool_and_handler_not_called(self):
        cfg = _cfg()
        for tool in sorted(READ_ONLY_TOOLS):
            with self.subTest(tool=tool):
                result, ct = _call(cfg, _tv("agent", "a1"), tool)
                self.assertTrue(result["isError"])
                self.assertIn("USE_TOOL_BROKER", result["content"][0]["text"])
                self.assertIn("agent_id=a1", result["content"][0]["text"])
                ct.assert_not_called()

    def test_agent_rejection_is_audited(self):
        with self.assertLogs("soar_mcp.audit", level="INFO") as cm:
            _call(_cfg(), _tv("agent", "a1"), "get_case", {"case_id": 1})
        self.assertTrue(any("outcome=denied:use_tool_broker" in line for line in cm.output))

    def test_agent_exception_runs_and_is_marked_in_audit(self):
        with self.assertLogs("soar_mcp.audit", level="INFO") as cm:
            result, ct = _call(_cfg(["get_soar_info"]), _tv("agent", "a1"), "get_soar_info")
        self.assertFalse(result["isError"])
        ct.assert_called_once()
        self.assertTrue(any("outcome=ok:agent_read_exception" in line for line in cm.output))

    def test_agent_write_tool_proceeds_with_plain_ok(self):
        with self.assertLogs("soar_mcp.audit", level="INFO") as cm:
            result, ct = _call(_cfg(), _tv("agent", "a1"), "add_case_note",
                               {"case_id": 1, "content": "x"})
        self.assertFalse(result["isError"])
        ct.assert_called_once()
        self.assertTrue(any("outcome=ok " in line for line in cm.output))

    def test_human_broker_legacy_read_unchanged(self):
        for tv in (_tv("mensch"), _tv("broker"), None):
            with self.subTest(principal=getattr(tv, "principal_type", "legacy")):
                result, ct = _call(_cfg(), tv, "get_case", {"case_id": 1})
                self.assertFalse(result["isError"])
                ct.assert_called_once()

    def test_disabled_and_scoped_checks_still_win(self):
        cfg = _cfg()
        cfg.enabled_tools = {"add_case_note"}             # get_case disabled
        result, ct = _call(cfg, _tv("agent", "a1"), "get_case")
        self.assertIn("is disabled", result["content"][0]["text"])
        ct.assert_not_called()
        result, ct = _call(_cfg(), _tv("agent", "a1", allowed_tools=["add_case_note"]), "get_case")
        self.assertIn("allow-list", result["content"][0]["text"])
        ct.assert_not_called()


if __name__ == "__main__":
    unittest.main()
