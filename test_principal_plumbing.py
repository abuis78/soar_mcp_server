"""SPEC-MCP Phase 2.3: caller identity (Principal) reaches call_tool and the
policy gate (MCP-W04 / AN-08; concept OQ-7 legacy = mensch).

Pure plumbing: no behaviour change for existing callers that pass actor_id.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from soar_mcp_config import ALL_TOOLS, McpServerConfig
from soar_mcp_handler import SoarMcpRestHandler
from soar_mcp_tokens import PRINCIPAL_AGENT, PRINCIPAL_BROKER, PRINCIPAL_HUMAN, Principal, TokenVerification
from soar_mcp_tools import call_tool


def _tv(principal_type="mensch", agent_id=None, **kw):
    return TokenVerification(valid=True, token_id="tok_x", label="lbl", soar_user_id="alice",
                             soar_call_token="ph-secret-value", allowed_tools=None,
                             principal_type=principal_type, agent_id=agent_id, **kw)


class _FakeClient:
    def get(self, *_a, **_k):
        return {}, None


class PrincipalTest(unittest.TestCase):
    def test_legacy_full_token_is_human_without_identity(self):
        p = Principal.from_verification(None)
        self.assertEqual(p.principal_type, PRINCIPAL_HUMAN)
        self.assertTrue(p.legacy)
        self.assertIsNone(p.token_id)
        self.assertIsNone(p.soar_user_id)
        self.assertIsNone(p.actor_id)
        self.assertIsNone(p.agent_id)
        self.assertFalse(p.is_agent)
        self.assertFalse(p.is_broker)

    def test_human_scoped_token(self):
        p = Principal.from_verification(_tv())
        self.assertEqual((p.principal_type, p.token_id, p.soar_user_id, p.label, p.legacy),
                         (PRINCIPAL_HUMAN, "tok_x", "alice", "lbl", False))
        self.assertEqual(p.actor_id, "alice")
        self.assertIsNone(p.agent_id)

    def test_agent_token_carries_agent_id(self):
        p = Principal.from_verification(_tv("agent", "triage_agent"))
        self.assertTrue(p.is_agent)
        self.assertEqual(p.agent_id, "triage_agent")

    def test_non_agent_never_carries_agent_id(self):
        p = Principal.from_verification(_tv("broker", "leaked"))
        self.assertTrue(p.is_broker)
        self.assertIsNone(p.agent_id)
        p = Principal.from_verification(_tv("mensch", "leaked"))
        self.assertIsNone(p.agent_id)

    def test_missing_principal_type_defaults_to_human(self):
        tv = _tv()
        tv.principal_type = ""
        self.assertEqual(Principal.from_verification(tv).principal_type, PRINCIPAL_HUMAN)

    def test_principal_is_immutable_and_never_holds_token_value(self):
        p = Principal.from_verification(_tv())
        with self.assertRaises(Exception):
            p.token_id = "other"  # type: ignore[misc]
        self.assertNotIn("ph-secret-value", repr(p))
        self.assertNotIn("ph-secret-value", p.audit_fields())

    def test_audit_fields(self):
        self.assertEqual(Principal.from_verification(None).audit_fields(),
                         "principal=legacy token_id=legacy agent_id=-")
        self.assertEqual(Principal.from_verification(_tv("agent", "a1")).audit_fields(),
                         "principal=agent token_id=tok_x agent_id=a1")


class CallToolPrincipalTest(unittest.TestCase):
    """Legacy policy_mode (""): the in-app gate receives actor_id and principal
    for write tools. Read tools never pass through a gate (Phase 2.5)."""

    def setUp(self):
        self.cfg = McpServerConfig()
        self.cfg.enabled_tools = set(ALL_TOOLS)
        self.client = _FakeClient()

    def test_principal_derives_actor_id_when_absent(self):
        with patch("soar_mcp_tools._policy_gate", return_value=None) as gate, \
                patch.dict("soar_mcp_tools._TOOL_HANDLERS", {"add_case_note": lambda c, cfg, a: "ok"}):
            out = call_tool("add_case_note", {"case_id": 1, "note": "n"}, self.client, self.cfg,
                            principal=Principal.from_verification(_tv()))
        self.assertEqual(out, "ok")
        args = gate.call_args.args
        self.assertEqual(args[4], "alice")                 # actor_id derived
        self.assertEqual(args[5].token_id, "tok_x")        # principal passed through

    def test_explicit_actor_id_wins_over_principal(self):
        with patch("soar_mcp_tools._policy_gate", return_value=None) as gate, \
                patch.dict("soar_mcp_tools._TOOL_HANDLERS", {"add_case_note": lambda c, cfg, a: "ok"}):
            call_tool("add_case_note", {"case_id": 1, "note": "n"}, self.client, self.cfg, actor_id="bob",
                      principal=Principal.from_verification(_tv()))
        self.assertEqual(gate.call_args.args[4], "bob")

    def test_legacy_principal_leaves_actor_id_none(self):
        with patch("soar_mcp_tools._policy_gate", return_value=None) as gate, \
                patch.dict("soar_mcp_tools._TOOL_HANDLERS", {"add_case_note": lambda c, cfg, a: "ok"}):
            call_tool("add_case_note", {"case_id": 1, "note": "n"}, self.client, self.cfg,
                      principal=Principal.from_verification(None))
        self.assertIsNone(gate.call_args.args[4])
        self.assertTrue(gate.call_args.args[5].legacy)

    def test_old_call_style_without_principal_unchanged(self):
        with patch("soar_mcp_tools._policy_gate", return_value=None) as gate, \
                patch.dict("soar_mcp_tools._TOOL_HANDLERS", {"add_case_note": lambda c, cfg, a: "ok"}):
            out = call_tool("add_case_note", {"case_id": 1, "note": "n"}, self.client, self.cfg, actor_id="carol")
        self.assertEqual(out, "ok")
        self.assertEqual(gate.call_args.args[4], "carol")
        self.assertIsNone(gate.call_args.args[5])

    def test_run_playbook_policy_hold_unchanged_with_principal(self):
        """AC-11: the legacy in-app gate still keys on actor_id only."""
        cfg = McpServerConfig()
        cfg.enabled_tools = set(ALL_TOOLS)
        cfg.policy_enabled = True
        with patch("soar_mcp_tools._policy_gate", wraps=None) as gate:
            gate.return_value = "⏸ held"
            out = call_tool("run_playbook", {"case_id": 1, "playbook_id": 1}, self.client, cfg,
                            principal=Principal.from_verification(_tv()))
        self.assertEqual(out, "⏸ held")
        self.assertEqual(gate.call_args.args[4], "alice")


class HandlerPassesPrincipalTest(unittest.TestCase):
    def _call(self, tv, tool="get_soar_info", args=None):
        cfg = McpServerConfig()
        cfg.enabled_tools = set(ALL_TOOLS)
        h = SoarMcpRestHandler.__new__(SoarMcpRestHandler)
        with patch("soar_mcp_handler.call_tool", return_value="fine") as ct:
            h._handle_tools_call({"name": tool, "arguments": dict(args or {})}, _FakeClient(), cfg, tv)
        return ct.call_args.kwargs

    def test_scoped_human_token(self):
        kw = self._call(_tv())
        self.assertEqual(kw["actor_id"], "alice")
        self.assertEqual(kw["principal"].principal_type, PRINCIPAL_HUMAN)
        self.assertEqual(kw["principal"].token_id, "tok_x")
        self.assertFalse(kw["principal"].legacy)

    def test_agent_token_on_write_tool(self):
        kw = self._call(_tv("agent", "a1"), tool="add_case_note")
        self.assertEqual(kw["principal"].principal_type, PRINCIPAL_AGENT)
        self.assertEqual(kw["principal"].agent_id, "a1")

    def test_broker_token(self):
        kw = self._call(_tv("broker"), args={"broker_aufruf_id": "tb-1"})  # MCP-L04 (Phase 4.2)
        self.assertEqual(kw["principal"].principal_type, PRINCIPAL_BROKER)

    def test_legacy_token(self):
        kw = self._call(None)
        self.assertIsNone(kw["actor_id"])
        self.assertTrue(kw["principal"].legacy)
        self.assertEqual(kw["principal"].principal_type, PRINCIPAL_HUMAN)


if __name__ == "__main__":
    unittest.main()
