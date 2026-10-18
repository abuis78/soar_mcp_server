"""SPEC-MCP MCP-G05: audit lines carry the caller's principal and correlation ids.

Covers the pre-call 'tool_call' line and the post-call 'tool_result' line.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from soar_mcp_config import ALL_TOOLS, McpServerConfig
from soar_mcp_handler import SoarMcpRestHandler
from soar_mcp_tokens import TokenVerification

_RAW = "soarmcp_THIS_RAW_TOKEN_MUST_NEVER_APPEAR_IN_LOGS_abcdef"


def _handler():
    return SoarMcpRestHandler.__new__(SoarMcpRestHandler)


def _tv(principal_type="mensch", agent_id=None):
    return TokenVerification(valid=True, token_id="tok_abc", label="lbl",
                             soar_user_id="u", soar_call_token=_RAW,
                             principal_type=principal_type, agent_id=agent_id)


def _cfg():
    cfg = McpServerConfig()
    cfg.enabled_tools = set(ALL_TOOLS)
    return cfg


class _AuditBase(unittest.TestCase):
    def _run(self, tv, tool="add_case_note", arguments=None, result="done"):
        """Call the handler with call_tool mocked; return the captured audit lines."""
        with self.assertLogs("soar_mcp.audit", level="INFO") as cm, \
                patch("soar_mcp_handler.call_tool", return_value=result):
            _handler()._handle_tools_call({"name": tool, "arguments": arguments or {}},
                                          object(), _cfg(), tv)
        return cm.output


def _line(lines, prefix):
    hits = [l for l in lines if prefix in l]
    assert len(hits) == 1, (prefix, lines)
    return hits[0]


class AuditIdentityTest(_AuditBase):
    def test_human_token_fields(self):
        call = _line(self._run(_tv("mensch")), "tool_call ")
        self.assertIn("principal=mensch", call)
        self.assertIn("token_id=tok_abc", call)
        self.assertIn("label=lbl", call)
        self.assertIn("agent_id=-", call)
        self.assertIn("lauf_id=-", call)
        self.assertIn("broker_aufruf_id=-", call)

    def test_agent_token_fields_with_lauf_id(self):
        out = self._run(_tv("agent", "triage"), "add_case_note",
                   {"case_id": 1, "content": "x", "lauf_id": "r-8812"})
        for prefix in ("tool_call ", "tool_result "):
            line = _line(out, prefix)
            self.assertIn("principal=agent", line)
            self.assertIn("agent_id=triage", line)
            self.assertIn("lauf_id=r-8812", line)

    def test_broker_token_fields_with_aufruf_id(self):
        out = self._run(_tv("broker"), "get_case", {"case_id": 1, "broker_aufruf_id": "tb-42"})
        self.assertIn("principal=broker", _line(out, "tool_call "))
        self.assertIn("broker_aufruf_id=tb-42", _line(out, "tool_result "))

    def test_legacy_token_fields(self):
        call = _line(self._run(None), "tool_call ")
        self.assertIn("principal=legacy", call)
        self.assertIn("token_id=legacy", call)

    def test_raw_token_never_logged_and_args_redacted(self):
        out = self._run(_tv("mensch"), "add_case_note",
                   {"case_id": 1, "content": "x", "auth_token": "ph_SECRET_VALUE_123"})
        joined = "\n".join(out)
        self.assertNotIn(_RAW, joined)
        self.assertNotIn("ph_SECRET_VALUE_123", joined)


class AuditResultLineTest(_AuditBase):
    def test_result_ok(self):
        self.assertIn("result=ok", _line(self._run(_tv(), result="Note added."), "tool_result "))

    def test_result_error(self):
        self.assertIn("result=error", _line(self._run(_tv(), result="Error: nope"), "tool_result "))

    def test_result_policy_blocked(self):
        self.assertIn("result=policy_blocked",
                      _line(self._run(_tv(), result="⛔ Blocked by policy (DENY): x"), "tool_result "))

    def test_result_policy_hold(self):
        self.assertIn("result=policy_hold",
                      _line(self._run(_tv(), result="⏸ Approval required by policy"), "tool_result "))

    def test_denied_calls_have_no_result_line(self):
        cfg = _cfg(); cfg.enabled_tools = {"get_case"}
        with self.assertLogs("soar_mcp.audit", level="INFO") as cm, \
                patch("soar_mcp_handler.call_tool") as ct:
            _handler()._handle_tools_call({"name": "add_case_note", "arguments": {}},
                                          object(), cfg, _tv())
        ct.assert_not_called()
        self.assertTrue(any("outcome=denied:disabled" in l for l in cm.output))
        self.assertFalse(any("tool_result " in l for l in cm.output))

    def test_classifier(self):
        c = SoarMcpRestHandler._classify_result
        self.assertEqual(c("fine", False), "ok")
        self.assertEqual(c("Error: x", True), "error")
        self.assertEqual(c("  ⛔ nope", True), "policy_blocked")
        self.assertEqual(c("⏸ wait", False), "policy_hold")


if __name__ == "__main__":
    unittest.main()
