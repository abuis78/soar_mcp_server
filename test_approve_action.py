"""SPEC-MCP Phase 3.4: tool approve_action(freigabe_id) (MCP-W06, OQ-7, OQ-11, OQ-16).

Runs against StubPolicyClient and a temp held-action store — no network.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

import policy.service_gate as sg
from policy.client import PolicyClientError, PolicyDecision, StubPolicyClient, approval_ref
from policy.held_actions import HeldActionStore
from soar_mcp_config import ALL_TOOLS, GATE_TOOLS, READ_ONLY_TOOLS, McpServerConfig
from soar_mcp_handler import SoarMcpRestHandler
from soar_mcp_tokens import Principal, TokenVerification
from soar_mcp_tools import TOOL_SCHEMAS, _WRITE_TOOLS, call_tool
from test_policy_service_gate import _FakeClient, _HANDLER_PATCH, _cfg, _principal


def _human(user):
    return Principal.from_verification(TokenVerification(
        valid=True, token_id=f"tok_{user}", label="l", soar_user_id=user, principal_type="mensch"))


class _Base(unittest.TestCase):
    def setUp(self):
        self.stub = StubPolicyClient()
        sg.set_policy_client_override(self.stub)
        self.addCleanup(sg.set_policy_client_override, None)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.held = HeldActionStore(os.path.join(tmp.name, "held_actions.json"))
        sg.set_held_store_override(self.held)
        self.addCleanup(sg.set_held_store_override, None)
        self.client = _FakeClient()
        self.executed = []
        handlers = dict(_HANDLER_PATCH)
        handlers["add_case_note"] = lambda c, cfg, a: self.executed.append(dict(a)) or "ran:add_case_note"
        hp = patch.dict("soar_mcp_tools._TOOL_HANDLERS", handlers)
        hp.start()
        self.addCleanup(hp.stop)
        self.cfg = _cfg()
        self.cfg.enabled_tools.add("approve_action")

    def hold(self, fid="ap-1", noetig=2, requester="alice"):
        self.stub.decision = PolicyDecision(entscheidung_id="pm-10", gate="APPROVE_2PERSON" if noetig == 2
                                            else "APPROVE_1CLICK", freigaben_noetig=noetig, freigabe_id=fid,
                                            ablauf="2099-01-01T00:00:00Z")
        out = call_tool("add_case_note", {"case_id": 5, "note": "n", "confirm_token": "c"}, self.client, self.cfg,
                        principal=_human(requester))
        self.assertTrue(out.startswith("⏸"), out)
        self.stub.add_approval(fid, noetig=noetig, initiator=requester)
        self.stub.calls.clear()
        return fid

    def approve(self, user, fid="ap-1", cfg=None, principal=None):
        return call_tool("approve_action", {"freigabe_id": fid}, self.client, cfg or self.cfg,
                         principal=principal or _human(user))


class ApproveActionFlowTest(_Base):
    def test_two_person_flow_executes_on_completing_call(self):
        fid = self.hold()
        out = self.approve("bob")
        self.assertTrue(out.startswith("⏸"), out)
        self.assertIn("1/2", out)
        self.assertIn('approve_action(freigabe_id="ap-1")', out)
        self.assertEqual(self.executed, [])
        out = self.approve("bob")
        self.assertIn("already approved", out)
        self.assertEqual(self.executed, [])
        with self.assertLogs("soar_mcp.policy", level="INFO") as cm:
            out = self.approve("carol")
        self.assertTrue(out.startswith("✅"), out)
        self.assertIn("ran:add_case_note", out)
        self.assertIn("approved by carol", out)
        self.assertIn("requested by alice", out)
        self.assertEqual(self.executed, [{"case_id": 5, "note": "n"}])  # held args, no gate args
        self.assertEqual([c[0] for c in self.stub.calls], ["approve", "approve", "approve", "consume"])
        self.assertEqual(self.stub.calls[-1][1][1]["aktion"]["art"], "add_case_note")
        self.assertIsNone(self.held.get(fid))
        line = "\n".join(cm.output)
        self.assertIn(f"approve_action executed tool=add_case_note freigabe_ref={approval_ref(fid)} entscheidung_id=pm-10", line)
        self.assertNotIn("ap-1", line)  # PM-F42: approval ids never in clear text
        self.assertNotIn("tok_carol", line.replace("token_id=tok_carol", ""))  # identity only via audit fields
        # Nothing left to redeem.
        out = self.approve("carol")
        self.assertIn("No held action", out)

    def test_one_click_single_approver_executes(self):
        self.hold(noetig=1)
        out = self.approve("bob")
        self.assertTrue(out.startswith("✅"))
        self.assertEqual(len(self.executed), 1)

    def test_requester_cannot_approve(self):
        self.hold()
        out = self.approve("alice")
        self.assertIn("cannot approve it yourself", out)
        self.assertEqual(self.executed, [])
        self.assertIsNotNone(self.held.get("ap-1"))

    def test_execution_bypasses_require_confirmation(self):
        """The policy approval is the stronger confirmation."""
        self.cfg.require_confirmation = True
        self.hold(noetig=1)
        out = self.approve("bob")
        self.assertTrue(out.startswith("✅"), out)
        self.assertNotIn("Confirmation required", out)

    def test_held_tool_disabled_refuses_before_consume(self):
        fid = self.hold(noetig=1)
        self.cfg.enabled_tools.discard("add_case_note")
        out = self.approve("bob")
        self.assertTrue(out.startswith("⛔"), out)
        self.assertIn("disabled", out)
        self.assertNotIn("consume", [c[0] for c in self.stub.calls])
        self.assertIsNotNone(self.held.get(fid))
        self.assertEqual(self.stub.approvals[fid]["status"], "approved")  # retry possible after enabling

    def test_consume_refused_never_executes(self):
        self.hold(noetig=1)
        self.stub.consume_ok = False
        out = self.approve("bob")
        self.assertIn("consume refused", out)
        self.assertIn("EXPIRED", out)
        self.assertEqual(self.executed, [])

    def test_halted_policy_manager_refuses_approval(self):
        self.hold(noetig=1)
        self.stub.halted = True
        out = self.approve("bob")
        self.assertIn("HALTED", out)
        self.assertEqual(self.executed, [])

    def test_policy_manager_unavailable_is_fail_closed(self):
        fid = self.hold(noetig=1)
        self.stub.reachable = False
        out = self.approve("bob")
        self.assertTrue(out.startswith("⛔"))
        self.assertIn("unavailable", out)
        self.assertIsNotNone(self.held.get(fid))

    def test_rejected_or_expired_approval(self):
        fid = self.hold(noetig=1)
        self.stub.approvals[fid]["status"] = "rejected"
        out = self.approve("bob")
        self.assertTrue(out.startswith("⛔"), out)
        self.assertIn("rejected", out)
        self.assertEqual(self.executed, [])

    def test_unknown_freigabe_id(self):
        out = self.approve("bob", fid="ap-nope")
        self.assertIn("No held action", out)
        self.assertEqual(self.stub.calls, [])
        out = call_tool("approve_action", {}, self.client, self.cfg, principal=_human("bob"))
        self.assertIn("needs freigabe_id", out)


class ApproveActionPrincipalTest(_Base):
    def test_only_humans_with_identity_can_approve(self):
        self.hold()
        for label, principal in (("agent", _principal("agent", "a1")), ("broker", _principal("broker")),
                                 ("legacy", _principal("legacy"))):
            with self.subTest(principal=label):
                out = self.approve(None, principal=principal)
                self.assertTrue(out.startswith("⛔"), out)
                self.assertIn("human analysts", out)
        self.assertEqual(self.stub.calls, [])
        self.assertEqual(self.executed, [])

    def test_legacy_mode_explains_approval_token(self):
        out = self.approve("bob", cfg=_cfg(mode=""))
        self.assertTrue(out.startswith("ℹ️"), out)
        self.assertIn("approval_token", out)
        self.assertEqual(self.stub.calls, [])

    def test_invalid_mode_refuses(self):
        out = self.approve("bob", cfg=_cfg(mode="embedded"))
        self.assertIn("policy_mode", out)
        self.assertEqual(self.stub.calls, [])


def _tv(principal_type="mensch", agent_id=None):
    return TokenVerification(valid=True, token_id="tok_x", label="t", soar_user_id="u", soar_call_token="ph",
                             allowed_tools=None, principal_type=principal_type, agent_id=agent_id)


class ApproveActionCatalogTest(unittest.TestCase):
    def test_gate_tool_is_neither_read_nor_write(self):
        self.assertEqual(GATE_TOOLS, {"approve_action"})
        self.assertIn("approve_action", ALL_TOOLS)
        self.assertNotIn("approve_action", READ_ONLY_TOOLS)
        self.assertNotIn("approve_action", _WRITE_TOOLS)
        self.assertEqual(len(_WRITE_TOOLS), 12)
        self.assertNotIn("approve_action", McpServerConfig().enabled_tools)  # off by default
        props = TOOL_SCHEMAS["approve_action"]["inputSchema"]["properties"]
        self.assertEqual(set(props), {"freigabe_id"})  # no agent_context, no write-tool gate args
        self.assertEqual(TOOL_SCHEMAS["approve_action"]["inputSchema"]["required"], ["freigabe_id"])

    def _names(self, tv):
        cfg = McpServerConfig()
        cfg.enabled_tools = set(ALL_TOOLS)
        h = SoarMcpRestHandler.__new__(SoarMcpRestHandler)
        return {t["name"] for t in h._handle_tools_list(cfg, tv)["tools"]}

    def test_hidden_from_agent_and_broker_visible_to_humans(self):
        self.assertIn("approve_action", self._names(None))
        self.assertIn("approve_action", self._names(_tv("mensch")))
        self.assertNotIn("approve_action", self._names(_tv("agent", "a1")))
        self.assertNotIn("approve_action", self._names(_tv("broker")))

    def test_tool_call_audit_never_carries_the_raw_freigabe_id(self):
        """PM-F42 review of #172: approve_action(freigabe_id=...) and redemptions
        <tool>(..., freigabe_id=...) reach the audit log as #<approval_ref>."""
        cfg = McpServerConfig()
        cfg.enabled_tools = set(ALL_TOOLS)
        h = SoarMcpRestHandler.__new__(SoarMcpRestHandler)
        for tool, args in (("approve_action", {"freigabe_id": "ap-7731"}),
                           ("add_case_note", {"case_id": 1, "note": "n", "freigabe_id": "ap-7731"})):
            with self.subTest(tool=tool):
                with patch("soar_mcp_handler.call_tool", return_value="fine"), \
                        self.assertLogs("soar_mcp.audit", level="INFO") as cm:
                    h._handle_tools_call({"name": tool, "arguments": args}, _FakeClient(), cfg, _tv("mensch"))
                log = "\n".join(cm.output)
                self.assertIn("tool_call", log)
                self.assertIn("#" + approval_ref("ap-7731"), log)
                self.assertNotIn("ap-7731", log)

    def test_call_by_agent_or_broker_is_rejected(self):
        cfg = McpServerConfig()
        cfg.enabled_tools = set(ALL_TOOLS)
        h = SoarMcpRestHandler.__new__(SoarMcpRestHandler)
        for kind in ("agent", "broker"):
            with patch("soar_mcp_handler.call_tool") as ct:
                res = h._handle_tools_call({"name": "approve_action", "arguments": {"freigabe_id": "ap-1"}},
                                           _FakeClient(), cfg, _tv(kind, "a1" if kind == "agent" else None))
            self.assertTrue(res.get("isError"), kind)
            # agent: human-only predicate; broker: the read-only rule (Phase 4.1) fires first
            self.assertIn("human analysts" if kind == "agent" else "read tool", res["content"][0]["text"])
            ct.assert_not_called()
        with patch("soar_mcp_handler.call_tool", return_value="fine") as ct:
            res = h._handle_tools_call({"name": "approve_action", "arguments": {"freigabe_id": "ap-1"}},
                                       _FakeClient(), cfg, _tv("mensch"))
        self.assertFalse(res.get("isError"))
        ct.assert_called_once()


if __name__ == "__main__":
    unittest.main()
