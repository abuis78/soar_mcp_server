"""SPEC-MCP Phase 2.5: Policy Manager adapter for write tools in mode service
(MCP-W01..W05, W07, W09; G03/G04; AC-01, AC-02, AC-04, AC-11; OQ-8, OQ-13).

All tests run against StubPolicyClient — no network, no Policy Manager.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest.mock import patch

import policy.service_gate as sg
from policy.held_actions import HeldActionStore
from policy.client import PolicyClientError, PolicyDecision, StubPolicyClient, approval_ref
from soar_mcp_config import ALL_TOOLS, READ_ONLY_TOOLS, McpServerConfig
from soar_mcp_tokens import Principal, TokenVerification
from soar_mcp_tools import _WRITE_TOOLS, call_tool

AGENT_CTX = {
    "lauf_id": "r-1", "stufe": 2, "domaene": "cyber", "tipping_off": "leise",
    "beleg_ids": ["tb-1"],
    "urteil": {"empfehlung": "do it", "gegenargumente": ["x"], "unsicherheiten": ["y"], "konfidenz": 0.8},
}


class _FakeClient:
    def __init__(self):
        self.calls = []

    def get(self, path, params=None):
        self.calls.append(("get", path))
        if path.startswith("playbook/"):
            return {"id": 7, "name": "PB", "category": "Enrichment"}, None
        if path == "artifact":
            return {"data": [{"name": "srv-fs-01", "cef": {"destinationAddress": "10.0.0.5"}}]}, None
        return {}, None

    def post(self, path, body):
        self.calls.append(("post", path))
        return {}, None


def _cfg(mode="service", url="https://pm.local", policy_enabled=False, require_confirmation=False):
    c = McpServerConfig()
    c.enabled_tools = set(ALL_TOOLS)
    c.advisory_disclaimer = False
    c.policy_mode = mode
    c.policy_service_url = url
    c.policy_enabled = policy_enabled
    c.require_confirmation = require_confirmation
    return c


def _principal(kind="mensch", agent_id=None):
    if kind == "legacy":
        return Principal.from_verification(None)
    return Principal.from_verification(TokenVerification(
        valid=True, token_id="tok_x", label="l", soar_user_id="alice",
        principal_type=kind, agent_id=agent_id))


_HANDLER_PATCH = {name: (lambda c, cfg, a, _n=name: f"ran:{_n}") for name in _WRITE_TOOLS}


class _Base(unittest.TestCase):
    def setUp(self):
        self.stub = StubPolicyClient()
        sg.set_policy_client_override(self.stub)
        self.addCleanup(sg.set_policy_client_override, None)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.held = HeldActionStore(os.path.join(self.tmp.name, "held_actions.json"))
        sg.set_held_store_override(self.held)
        self.addCleanup(sg.set_held_store_override, None)
        self.client = _FakeClient()
        self._hp = patch.dict("soar_mcp_tools._TOOL_HANDLERS", _HANDLER_PATCH)
        self._hp.start()
        self.addCleanup(self._hp.stop)

    def call(self, tool, args=None, principal=None, cfg=None):
        return call_tool(tool, dict(args or {}), self.client, cfg or _cfg(),
                         principal=principal or _principal())


class ModeSelectionTest(_Base):
    def test_legacy_mode_never_calls_the_service(self):
        for tool in sorted(_WRITE_TOOLS):
            out = self.call(tool, {"case_id": 1, "playbook_id": 1, "container_id": 1}, cfg=_cfg(mode=""))
            self.assertTrue(out.startswith("ran:"), (tool, out))
        self.assertEqual(self.stub.calls, [])

    def test_legacy_mode_keeps_in_app_gate_for_run_playbook(self):
        with patch("soar_mcp_tools._policy_gate", return_value="⏸ held by in-app layer") as gate:
            out = self.call("run_playbook", {"case_id": 1, "playbook_id": 1}, cfg=_cfg(mode="", policy_enabled=True))
        self.assertEqual(out, "⏸ held by in-app layer")
        gate.assert_called_once()
        self.assertEqual(self.stub.calls, [])

    def test_invalid_mode_refuses_every_write_tool_without_execution(self):
        for mode in ("embedded", "whatever"):
            for tool in sorted(_WRITE_TOOLS):
                out = self.call(tool, {"case_id": 1}, cfg=_cfg(mode=mode))
                self.assertTrue(out.startswith("⛔"), (mode, tool, out))
                self.assertIn("policy_mode", out)
        out = self.call("add_case_note", {"case_id": 1, "note": "n"}, cfg=_cfg(mode="service", url=""))
        self.assertIn("policy_mode", out)
        self.assertEqual(self.stub.calls, [])

    def test_read_tools_never_gated_in_any_mode(self):
        with patch.dict("soar_mcp_tools._TOOL_HANDLERS", {"get_soar_info": lambda c, cfg, a: "info"}):
            for mode in ("", "service", "embedded"):
                self.assertEqual(self.call("get_soar_info", cfg=_cfg(mode=mode)), "info")
        self.assertEqual(self.stub.calls, [])

    def test_service_mode_skips_in_app_gate(self):
        with patch("soar_mcp_tools._policy_gate") as gate:
            out = self.call("run_playbook", {"case_id": 1, "playbook_id": 7})
        self.assertEqual(out, "ran:run_playbook")
        gate.assert_not_called()
        self.assertEqual(len(self.stub.calls), 1)


class DecideFlowTest(_Base):
    def test_every_write_tool_goes_through_decide(self):
        """AC-01: without a decision nothing is executed; with ALLOW everything runs."""
        for tool in sorted(_WRITE_TOOLS):
            with self.subTest(tool=tool):
                self.stub.calls.clear()
                args = {"case_id": 1, "playbook_id": 7, "container_id": 1, "dry_run": False, "note": "n"}
                out = self.call(tool, args)
                self.assertEqual(out, f"ran:{tool}")
                self.assertEqual(len(self.stub.calls), 1)
                self.assertEqual(self.stub.calls[0][1]["aktion"]["art"], tool)

    def test_deny_blocks_with_code_and_id(self):
        self.stub.decision = PolicyDecision(entscheidung_id="pm-9", gate="DENY", code="HALTED",
                                            begruendung=({"regel": "halt", "gate": "DENY"},))
        out = self.call("add_case_note", {"case_id": 1, "note": "n"})
        self.assertTrue(out.startswith("⛔"))
        self.assertIn("HALTED", out)
        self.assertIn("entscheidung_id=pm-9", out)
        self.assertIn("halt->DENY", out)

    def test_decision_log_carries_single_hash_or_dash(self):
        """PM-F42 review of #172: freigabe_ref is sha256(id)[:16] once (correlates with the
        Policy Manager's freigabe_hash), and "-" when the decision carries no id."""
        self.stub.decision = PolicyDecision(entscheidung_id="pm-10", gate="APPROVE_2PERSON",
                                            freigaben_noetig=2, freigabe_id="ap-5521")
        with self.assertLogs("soar_mcp.policy", level="INFO") as cm:
            self.call("delete_container", {"container_id": 5, "confirm": True})
        decision_lines = [l for l in cm.output if "service decision" in l]
        self.assertEqual(len(decision_lines), 1)
        self.assertIn(f"freigabe_ref={approval_ref('ap-5521')} ", decision_lines[0])
        self.assertNotIn(approval_ref(approval_ref("ap-5521")), decision_lines[0])
        self.assertNotIn("ap-5521", decision_lines[0])
        self.stub.decision = PolicyDecision(entscheidung_id="pm-11", gate="ALLOW")
        with self.assertLogs("soar_mcp.policy", level="INFO") as cm:
            self.call("add_case_note", {"case_id": 1, "note": "n"})
        decision_lines = [l for l in cm.output if "service decision" in l]
        self.assertIn("freigabe_ref=- ", decision_lines[0])

    def test_approval_gate_holds_and_never_executes(self):
        self.stub.decision = PolicyDecision(entscheidung_id="pm-10", gate="APPROVE_2PERSON",
                                            freigaben_noetig=2, freigabe_id="ap-5521",
                                            ablauf="2026-10-19T10:00:00+02:00")
        out = self.call("delete_container", {"container_id": 5, "confirm": True})
        self.assertTrue(out.startswith("⏸"))
        for needle in ("2 distinct approver", "freigabe_id=ap-5521", "entscheidung_id=pm-10", "ablauf=2026-10-19",
                       'approve_action(freigabe_id="ap-5521")', 'delete_container again', "Nothing has been executed"):
            self.assertIn(needle, out)
        self.assertNotIn("ran:", out)

    def test_hold_remembers_the_action_for_redemption(self):
        """Phase 3.2 (OQ-16): the held action is stored under the freigabe_id."""
        self.stub.decision = PolicyDecision(entscheidung_id="pm-10", gate="APPROVE_2PERSON",
                                            freigaben_noetig=2, freigabe_id="ap-5521",
                                            ablauf="2099-01-01T00:00:00Z")
        self.call("add_case_note", {"case_id": 5, "note": "n", "confirm_token": "x"})
        held = self.held.get("ap-5521")
        self.assertIsNotNone(held)
        self.assertEqual((held.tool, held.args, held.entscheidung_id, held.gate, held.noetig, held.initiator,
                          held.principal_type),
                         ("add_case_note", {"case_id": 5, "note": "n"}, "pm-10", "APPROVE_2PERSON", 2, "alice",
                          "mensch"))
        self.assertEqual(held.request, self.stub.calls[-1][1])
        self.assertGreater(held.expires_at, 4_000_000_000)
        # ALLOW and DENY never leave a held action behind.
        self.stub.decision = PolicyDecision(entscheidung_id="pm-11", gate="DENY")
        self.call("add_case_note", {"case_id": 6, "note": "n"})
        self.assertEqual(self.held.count(), 1)

    def test_hold_store_failure_is_reported_but_never_executes(self):
        self.stub.decision = PolicyDecision(entscheidung_id="pm-10", gate="APPROVE_1CLICK", freigabe_id="ap-1")
        with patch.object(self.held, "put", side_effect=OSError("disk full")):
            out = self.call("add_case_note", {"case_id": 5, "note": "n"})
        self.assertTrue(out.startswith("⏸"))
        self.assertIn("could not be stored", out)
        self.assertNotIn("approve_action(", out)
        self.assertNotIn("ran:", out)

    def test_one_click_defaults_to_one_approver(self):
        self.stub.decision = PolicyDecision(entscheidung_id="pm-11", gate="APPROVE_1CLICK", freigabe_id="ap-1")
        out = self.call("update_case_status", {"case_id": 1, "status": "closed"})
        self.assertIn("1 distinct approver", out)

    def test_service_unavailable_blocks_without_fallback(self):
        """AC-02 / MCP-G04."""
        for kind in ("timeout", "unreachable", "http", "contract", "tls"):
            self.stub.decision = PolicyClientError("boom", kind)
            out = self.call("add_case_note", {"case_id": 1, "note": "n"})
            self.assertTrue(out.startswith("⛔"), out)
            self.assertIn(kind, out)
            self.assertIn("No fallback", out)

    def test_unexpected_client_exception_blocks(self):
        self.stub.decision = lambda req: (_ for _ in ()).throw(RuntimeError("bug"))
        out = self.call("add_case_note", {"case_id": 1, "note": "n"})
        self.assertTrue(out.startswith("⛔"))
        self.assertIn("RuntimeError", out)

    def test_allow_then_require_confirmation_still_applies(self):
        """MCP-W09: confirmation stays as a human aid after ALLOW."""
        out = self.call("add_case_note", {"case_id": 1, "note": "n"}, cfg=_cfg(require_confirmation=True))
        self.assertIn("Confirmation required", out)
        self.assertEqual(len(self.stub.calls), 1)

    def test_decision_is_audited(self):
        self.stub.decision = PolicyDecision(entscheidung_id="pm-12", gate="ALLOW", policy_version="abc")
        with self.assertLogs("soar_mcp.policy", level="INFO") as cm:
            self.call("add_case_note", {"case_id": 1, "note": "n"}, principal=_principal("agent", "a1") and _principal())
        line = "\n".join(cm.output)
        self.assertIn("entscheidung_id=pm-12", line)
        self.assertIn("gate=ALLOW", line)
        self.assertIn("token_id=tok_x", line)
        self.assertIn("policy_version=abc", line)


class _ApprovalClient(_FakeClient):
    """Resolves the approval playbook by name and records playbook_run bodies."""

    def __init__(self, post_err=None, playbooks=({"id": 841, "name": "pm_freigabe"},)):
        super().__init__()
        self.bodies = []
        self.post_err = post_err
        self.playbooks = list(playbooks)

    def get(self, path, params=None):
        if path == "playbook":
            self.calls.append(("get", path))
            return {"data": self.playbooks}, None
        return super().get(path, params)

    def post(self, path, body):
        self.calls.append(("post", path))
        self.bodies.append((path, body))
        return ({}, self.post_err) if self.post_err else ({"playbook_run_id": 99}, None)


class ApprovalPlaybookTest(_Base):
    """Proposal B: on APPROVE_* the MCP starts the approval input playbook on the case."""

    def setUp(self):
        super().setUp()
        self.client = _ApprovalClient()
        self.stub.decision = PolicyDecision(entscheidung_id="pm-20", gate="APPROVE_2PERSON",
                                            freigaben_noetig=2, freigabe_id="ap-7788",
                                            ablauf="2099-01-01T00:00:00Z",
                                            begruendung=({"regel": "r1", "gate": "APPROVE_2PERSON"},))

    def _cfg_on(self, name="pm_freigabe"):
        c = _cfg()
        c.approval_playbook = name
        return c

    def _runs(self):
        return [b for p, b in self.client.bodies if p == "playbook_run"]

    def test_starts_input_playbook_with_seven_string_inputs(self):
        out = self.call("update_case_status", {"case_id": 5, "status": "closed"}, cfg=self._cfg_on())
        self.assertTrue(out.startswith("⏸"))
        self.assertNotIn("ran:", out)
        runs = self._runs()
        self.assertEqual(len(runs), 1)
        body = runs[0]
        self.assertEqual((body["container_id"], body["playbook_id"], body["scope"], body["run"]),
                         (5, 841, "new", True))
        self.assertIsInstance(body["inputs"], str)  # On-Prem 8.x: JSON-encoded string
        inputs = json.loads(body["inputs"])
        self.assertEqual(inputs, {
            "freigabe_id": "ap-7788", "noetig": "2", "initiator": "alice", "art": "update_case_status",
            "ziel": "case_id=5", "begruendung_kurz": "r1->APPROVE_2PERSON",
            "ablauf": "2099-01-01T00:00:00Z"})
        self.assertTrue(all(isinstance(v, str) for v in inputs.values()))
        self.assertIsNotNone(self.held.get("ap-7788"))

    def test_off_by_default_starts_nothing(self):
        self.call("update_case_status", {"case_id": 5, "status": "closed"})
        self.assertEqual(self._runs(), [])
        self.assertNotIn(("get", "playbook"), self.client.calls)

    def test_container_id_is_used_as_case(self):
        self.call("create_artifact", {"container_id": 12, "name": "a"}, cfg=self._cfg_on())
        self.assertEqual(self._runs()[0]["container_id"], 12)

    def test_no_case_no_start(self):
        self.call("create_container", {"name": "x", "label": "test"}, cfg=self._cfg_on())
        self.assertEqual(self._runs(), [])

    def test_allow_deny_and_store_failure_start_nothing(self):
        for decision in (PolicyDecision(entscheidung_id="pm-1", gate="ALLOW"),
                         PolicyDecision(entscheidung_id="pm-2", gate="DENY")):
            self.stub.decision = decision
            self.call("update_case_status", {"case_id": 5, "status": "closed"}, cfg=self._cfg_on())
        self.stub.decision = PolicyDecision(entscheidung_id="pm-3", gate="APPROVE_1CLICK", freigabe_id="ap-1")
        with patch.object(self.held, "put", side_effect=OSError("disk full")):
            self.call("update_case_status", {"case_id": 5, "status": "closed"}, cfg=self._cfg_on())
        self.stub.decision = PolicyDecision(entscheidung_id="pm-4", gate="APPROVE_1CLICK", freigabe_id="")
        self.call("update_case_status", {"case_id": 5, "status": "closed"}, cfg=self._cfg_on())
        self.assertEqual(self._runs(), [])

    def test_start_failure_keeps_hold_and_logs_ref_only(self):
        self.client = _ApprovalClient(post_err="HTTP 400 ap-7788 rejected")
        with self.assertLogs("soar_mcp.policy", level="INFO") as cm:
            out = self.call("update_case_status", {"case_id": 5, "status": "closed"}, cfg=self._cfg_on())
        self.assertTrue(out.startswith("⏸"))
        self.assertNotIn("ran:", out)
        self.assertIsNotNone(self.held.get("ap-7788"))
        lines = [l for l in cm.output if "approval playbook" in l]
        self.assertEqual(len(lines), 1)
        self.assertIn("not started", lines[0])
        self.assertIn(f"freigabe_ref={approval_ref('ap-7788')}", lines[0])
        self.assertNotIn("ap-7788", lines[0])

    def test_unresolvable_name_keeps_hold(self):
        self.client = _ApprovalClient(playbooks=())
        out = self.call("update_case_status", {"case_id": 5, "status": "closed"}, cfg=self._cfg_on())
        self.assertTrue(out.startswith("⏸"))
        self.assertEqual(self._runs(), [])
        self.assertIsNotNone(self.held.get("ap-7788"))

    def test_started_log_carries_ref_only(self):
        with self.assertLogs("soar_mcp.policy", level="INFO") as cm:
            self.call("update_case_status", {"case_id": 5, "status": "closed"}, cfg=self._cfg_on())
        lines = [l for l in cm.output if "approval playbook started" in l]
        self.assertEqual(len(lines), 1)
        self.assertIn(f"freigabe_ref={approval_ref('ap-7788')}", lines[0])
        self.assertNotIn("ap-7788", "\n".join(cm.output))

    def test_notice_says_request_was_sent(self):
        out = self.call("update_case_status", {"case_id": 5, "status": "closed"}, cfg=self._cfg_on())
        self.assertIn("approval request was sent", out)
        self.assertIn('approve_action(freigabe_id="ap-7788")', out)

    def test_notice_says_request_failed(self):
        self.client = _ApprovalClient(post_err="HTTP 500")
        out = self.call("update_case_status", {"case_id": 5, "status": "closed"}, cfg=self._cfg_on())
        self.assertIn("could not be sent to SOAR", out)
        self.assertIn('approve_action(freigabe_id="ap-7788")', out)

    def test_notice_unchanged_when_not_attempted(self):
        off = self.call("update_case_status", {"case_id": 5, "status": "closed"})
        no_case = self.call("create_container", {"name": "x", "label": "test"}, cfg=self._cfg_on())
        for out in (off, no_case):
            self.assertNotIn("approval request", out)
            self.assertNotIn("approval playbook", out)

    def test_start_is_not_a_tool_call_and_runs_no_second_decide(self):
        self.call("update_case_status", {"case_id": 5, "status": "closed"}, cfg=self._cfg_on())
        self.assertEqual(len(self.stub.calls), 1)


class RequestShapeTest(_Base):
    def _request(self, tool, args, principal=None):
        self.call(tool, args, principal=principal)
        return self.stub.calls[-1][1]

    def test_run_playbook_request_has_category_playbook_target_and_asset_values(self):
        req = self._request("run_playbook", {"case_id": 3, "playbook_id": 7, "scope": "new"})
        self.assertEqual(req["aktion"]["art"], "run_playbook")
        self.assertEqual(req["aktion"]["kategorie"], "Enrichment")
        self.assertEqual(req["aktion"]["playbook"], "PB")
        self.assertEqual(req["aktion"]["ziel"], ["case_id=3", "playbook_id=7"])
        self.assertEqual(req["aktion"]["parameter"], {"case_id": 3, "playbook_id": 7, "scope": "new"})
        self.assertIn("srv-fs-01", req["kontext"]["artefakt_werte"])
        self.assertIn("10.0.0.5", req["kontext"]["artefakt_werte"])
        self.assertNotIn("reversible", str(req))
        self.assertEqual(set(req), {"aktion", "kontext"})

    def test_request_matches_policy_client_base_wire(self):
        """Every key of DecisionRequest.to_wire() (PolicyManager P1.5) is present."""
        req = self._request("add_case_note", {"case_id": 1, "note": "n"})
        self.assertEqual(set(req["aktion"]), {"art", "kategorie", "playbook", "ziel", "parameter"})
        self.assertEqual(set(req["kontext"]), {"principal_type", "initiator", "agent_id", "lauf_id", "schritt_id",
                                               "domaene", "tipping_off", "beleg_ids", "urteil", "artefakt_werte"})
        self.assertEqual((req["aktion"]["kategorie"], req["aktion"]["playbook"]), ("", ""))
        req = self._request("add_case_note", {"case_id": 1, "note": "n", "agent_context": AGENT_CTX},
                            principal=_principal("agent", "a1"))
        self.assertIn("stufe", req["kontext"])
        self.assertIn("agent_konfidenz", req["kontext"])

    def test_initiator_for_human_agent_and_legacy(self):
        """kontext.principal_type / initiator / agent_id (MCP-W04, OQ-7)."""
        def ident(req):
            k = req["kontext"]
            return k["principal_type"], k["initiator"], k["agent_id"]
        req = self._request("add_case_note", {"case_id": 1, "note": "n"})
        self.assertEqual(ident(req), ("mensch", "alice", ""))
        self.assertNotIn("tok_x", str(req))  # token ids never travel
        req = self._request("add_case_note", {"case_id": 1, "note": "n", "agent_context": AGENT_CTX},
                            principal=_principal("agent", "triage"))
        self.assertEqual(ident(req), ("agent", "triage", "triage"))
        req = self._request("add_case_note", {"case_id": 1, "note": "n"}, principal=_principal("legacy"))
        self.assertEqual(ident(req), ("mensch", "", ""))
        self.assertEqual(sg.principal_identity(None), "")

    def test_gate_arguments_never_sent_as_parameters(self):
        req = self._request("add_case_note", {"case_id": 1, "note": "n", "approval_token": "t",
                                              "confirm_token": "c", "agent_context": {"stufe": 1}})
        self.assertEqual(set(req["aktion"]["parameter"]), {"case_id", "note"})
        self.assertEqual(req["kontext"]["stufe"], 1)
        # freigabe_id switches call_tool to the redeem path (3.3); the builder itself drops it too.
        req = sg.build_decide_request("add_case_note", {"case_id": 1, "freigabe_id": "ap-1"}, _principal(), None)
        self.assertEqual(set(req["aktion"]["parameter"]), {"case_id"})
        self.assertEqual(req["aktion"]["ziel"], ["case_id=1"])

    def test_agent_context_fields_land_in_kontext(self):
        req = self._request("update_case_severity", {"case_id": 1, "severity": "high", "agent_context": AGENT_CTX},
                            principal=_principal("agent", "a1"))
        for k in ("lauf_id", "stufe", "domaene", "tipping_off", "beleg_ids", "urteil"):
            self.assertEqual(req["kontext"][k], AGENT_CTX[k])
        self.assertEqual(req["kontext"]["agent_konfidenz"], 0.8)

    def test_correlation_ids_are_not_targets(self):
        req = self._request("add_case_note", {"case_id": 1, "note": "n", "lauf_id": "r", "broker_aufruf_id": "b"})
        self.assertEqual(req["aktion"]["ziel"], ["case_id=1"])

    def test_no_case_id_means_no_asset_lookup(self):
        self._request("create_container", {"name": "x", "label": "test"})
        self.assertNotIn(("get", "artifact"), self.client.calls)

    def test_enrichment_failure_still_decides(self):
        def boom(*_a):
            raise RuntimeError("soar down")
        with patch("soar_mcp_tools._collect_case_artifact_values", side_effect=boom):
            out = self.call("add_case_note", {"case_id": 1, "note": "n"})
        self.assertEqual(out, "ran:add_case_note")
        self.assertEqual(self.stub.calls[-1][1]["kontext"]["artefakt_werte"], [])


class AgentRulesTest(_Base):
    def test_agent_without_context_is_no_evidence_without_network(self):
        """AC-04."""
        out = self.call("add_case_note", {"case_id": 1, "note": "n"}, principal=_principal("agent", "a1"))
        self.assertTrue(out.startswith("⛔"))
        self.assertIn("NO_EVIDENCE", out)
        self.assertEqual(self.stub.calls, [])

    def test_agent_without_judgement_is_incomplete_judgement(self):
        ctx = {k: v for k, v in AGENT_CTX.items() if k != "urteil"}
        out = self.call("add_case_note", {"case_id": 1, "note": "n", "agent_context": ctx},
                        principal=_principal("agent", "a1"))
        self.assertIn("INCOMPLETE_JUDGEMENT", out)
        self.assertEqual(self.stub.calls, [])

    def test_malformed_context_blocks_for_everyone(self):
        out = self.call("add_case_note", {"case_id": 1, "note": "n", "agent_context": {"stufe": 9}})
        self.assertIn("INVALID_AGENT_CONTEXT", out)
        self.assertEqual(self.stub.calls, [])

    def test_agent_confidence_ignored_for_agents_and_audited(self):
        """MCP-W05."""
        with self.assertLogs("soar_mcp.policy", level="INFO") as cm:
            self.call("run_playbook", {"case_id": 1, "playbook_id": 7, "agent_confidence": 0.99,
                                       "agent_context": AGENT_CTX}, principal=_principal("agent", "a1"))
        req = self.stub.calls[-1][1]
        self.assertEqual(req["kontext"]["agent_konfidenz"], 0.8)
        self.assertIn("agent_confidence_ignored", "\n".join(cm.output))

    def test_human_agent_confidence_passes_through(self):
        self.call("run_playbook", {"case_id": 1, "playbook_id": 7, "agent_confidence": 0.3})
        self.assertEqual(self.stub.calls[-1][1]["kontext"]["agent_konfidenz"], 0.3)

    def test_broker_principal_also_goes_through_decide(self):
        out = self.call("add_case_note", {"case_id": 1, "note": "n"}, principal=_principal("broker"))
        self.assertEqual(out, "ran:add_case_note")
        self.assertEqual(self.stub.calls[-1][1]["kontext"]["principal_type"], "broker")
        self.assertEqual(self.stub.calls[-1][1]["kontext"]["initiator"], "alice")


class DryRunTest(_Base):
    def test_dry_runs_skip_decide_and_execute(self):
        """OQ-13: dry-runs are reads."""
        for tool, args in (("save_playbook_layout_only", {"playbook_id": 7}),
                           ("save_playbook_layout_only", {"playbook_id": 7, "dry_run": True}),
                           ("create_custom_function_draft", {"scm_id": 2}),
                           ("update_custom_function_draft", {"custom_function_id": 3, "dry_run": True})):
            with self.subTest(tool=tool):
                with self.assertLogs("soar_mcp.policy", level="INFO") as cm:
                    out = self.call(tool, args, principal=_principal("agent", "a1"))
                self.assertEqual(out, f"ran:{tool}")
                self.assertIn("skip=dry_run", "\n".join(cm.output))
        self.assertEqual(self.stub.calls, [])

    def test_real_write_goes_through_decide(self):
        self.stub.decision = PolicyDecision(entscheidung_id="pm-1", gate="DENY")
        out = self.call("save_playbook_layout_only", {"playbook_id": 7, "dry_run": False})
        self.assertTrue(out.startswith("⛔"))
        self.assertEqual(len(self.stub.calls), 1)

    def test_other_tools_are_never_dry_runs(self):
        self.assertFalse(sg.is_dry_run("add_case_note", {"dry_run": True}))
        self.assertTrue(sg.is_dry_run("save_playbook_layout_only", {}))
        self.assertFalse(sg.is_dry_run("save_playbook_layout_only", {"dry_run": False}))


class RedeemTest(_Base):
    """Phase 3.3: re-call with freigabe_id redeems a held action (MCP-W06, OQ-11, AC-05)."""

    ARGS = {"case_id": 5, "note": "n"}

    def _hold(self, fid="ap-1", noetig=2, principal=None):
        self.stub.decision = PolicyDecision(entscheidung_id="pm-10", gate="APPROVE_2PERSON",
                                            freigaben_noetig=noetig, freigabe_id=fid,
                                            ablauf="2099-01-01T00:00:00Z")
        out = self.call("add_case_note", self.ARGS, principal=principal)
        self.assertTrue(out.startswith("⏸"))
        self.stub.add_approval(fid, noetig=noetig, initiator="alice")
        self.stub.calls.clear()
        return fid

    def test_pending_approval_holds_without_consume(self):
        fid = self._hold()
        self.stub.approve(fid, "bob")
        self.stub.calls.clear()
        out = self.call("add_case_note", dict(self.ARGS, freigabe_id=fid))
        self.assertTrue(out.startswith("⏸"))
        self.assertIn("1/2", out)
        self.assertIn('approve_action(freigabe_id="ap-1")', out)
        self.assertEqual([c[0] for c in self.stub.calls], ["approval_status"])
        self.assertIsNotNone(self.held.get(fid))

    def test_approved_is_consumed_then_executed_once(self):
        fid = self._hold()
        self.stub.approve(fid, "bob")
        self.stub.approve(fid, "carol")
        self.stub.calls.clear()
        with self.assertLogs("soar_mcp.policy", level="INFO") as cm:
            out = self.call("add_case_note", dict(self.ARGS, freigabe_id=fid, confirm_token="c"))
        self.assertEqual(out, "ran:add_case_note")
        self.assertEqual([c[0] for c in self.stub.calls], ["approval_status", "consume"])
        self.assertEqual(self.stub.calls[1][1][0], fid)
        self.assertEqual(self.stub.calls[1][1][1]["aktion"]["art"], "add_case_note")  # the held request
        log = "\n".join(cm.output)
        self.assertIn(f"redeemed freigabe_ref={approval_ref(fid)} entscheidung_id=pm-10", log)
        self.assertNotIn("ap-1", log)  # PM-F42: approval ids never in clear text
        self.assertIsNone(self.held.get(fid))
        # Second redemption: nothing held any more, nothing executed.
        out = self.call("add_case_note", dict(self.ARGS, freigabe_id=fid))
        self.assertTrue(out.startswith("⛔"))
        self.assertIn("No held action", out)

    def test_changed_arguments_or_tool_are_refused_locally(self):
        fid = self._hold()
        out = self.call("add_case_note", {"case_id": 5, "note": "CHANGED", "freigabe_id": fid})
        self.assertIn("ACTION_CHANGED", out)
        out = self.call("update_case_status", {"case_id": 5, "status": "closed", "freigabe_id": fid})
        self.assertIn("ACTION_CHANGED", out)
        self.assertEqual(self.stub.calls, [])
        self.assertIsNotNone(self.held.get(fid))

    def test_rejected_expired_consumed_refuse_and_forget(self):
        for state in ("rejected", "expired", "consumed"):
            with self.subTest(state=state):
                fid = self._hold(fid=f"ap-{state}")
                self.stub.approvals[fid]["status"] = state
                out = self.call("add_case_note", dict(self.ARGS, freigabe_id=fid))
                self.assertTrue(out.startswith("⛔"))
                self.assertIn(state, out)
                self.assertIsNone(self.held.get(fid))
                self.assertNotIn("consume", [c[0] for c in self.stub.calls])

    def test_consume_refused_never_executes(self):
        fid = self._hold(noetig=1)
        self.stub.approve(fid, "bob")
        self.stub.consume_ok = False  # stub answers gueltig=false, EXPIRED
        out = self.call("add_case_note", dict(self.ARGS, freigabe_id=fid))
        self.assertTrue(out.startswith("⛔"))
        self.assertIn("EXPIRED", out)
        self.assertIsNone(self.held.get(fid))

    def test_service_unavailable_on_redeem_is_fail_closed(self):
        fid = self._hold(noetig=1)
        self.stub.approve(fid, "bob")
        self.stub.reachable = False
        out = self.call("add_case_note", dict(self.ARGS, freigabe_id=fid))
        self.assertTrue(out.startswith("⛔"))
        self.assertIn("unavailable", out)
        self.assertIsNotNone(self.held.get(fid))  # approval untouched, can be retried

    def test_unknown_freigabe_id_is_refused_without_network(self):
        out = self.call("add_case_note", dict(self.ARGS, freigabe_id="ap-nope"))
        self.assertIn("No held action", out)
        self.assertEqual(self.stub.calls, [])
        out = self.call("add_case_note", dict(self.ARGS, freigabe_id="../x"))
        self.assertTrue(out.startswith("⛔"))
        self.assertEqual(self.stub.calls, [])

    def test_redeem_skips_decide_and_agent_context_check(self):
        """The held request was validated at hold time; redemption needs no new context."""
        fid = self._hold(noetig=1)
        self.stub.approve(fid, "bob")
        out = self.call("add_case_note", dict(self.ARGS, freigabe_id=fid), principal=_principal("agent", "a1"))
        self.assertEqual(out, "ran:add_case_note")
        self.assertNotIn("decide", [c[0] for c in self.stub.calls])

    def test_legacy_mode_ignores_service_redeem_path(self):
        out = self.call("add_case_note", dict(self.ARGS, freigabe_id="ap-1"), cfg=_cfg(mode=""))
        self.assertEqual(out, "ran:add_case_note")
        self.assertEqual(self.stub.calls, [])


class HaltTest(_Base):
    """Phase 3.5: emergency stop for the agent chain (MCP-W08, AC-09, PM-F31/F33)."""

    def test_halted_blocks_agent_writes_without_decide(self):
        self.stub.halted = True
        out = self.call("add_case_note", {"case_id": 1, "note": "n", "agent_context": AGENT_CTX},
                        principal=_principal("agent", "a1"))
        self.assertTrue(out.startswith("⛔"), out)
        self.assertIn("HALTED", out)
        self.assertEqual([c[0] for c in self.stub.calls], ["halt_status"])

    def test_halted_blocks_agent_redeem(self):
        self.stub.decision = PolicyDecision(entscheidung_id="pm-1", gate="APPROVE_1CLICK", freigabe_id="ap-1",
                                            ablauf="2099-01-01T00:00:00Z")
        self.call("add_case_note", {"case_id": 1, "note": "n"})
        self.stub.add_approval("ap-1", status="approved", erteilt=1, noetig=1, initiator="alice")
        self.stub.halted = True
        self.stub.calls.clear()
        out = self.call("add_case_note", {"case_id": 1, "note": "n", "freigabe_id": "ap-1"},
                        principal=_principal("agent", "a1"))
        self.assertIn("HALTED", out)
        self.assertEqual([c[0] for c in self.stub.calls], ["halt_status"])
        self.assertIsNotNone(self.held.get("ap-1"))

    def test_humans_brokers_and_legacy_keep_working(self):
        self.stub.halted = True
        for p in (_principal(), _principal("broker"), _principal("legacy")):
            with self.subTest(principal=p.principal_type + ("/legacy" if p.legacy else "")):
                self.stub.calls.clear()
                out = self.call("add_case_note", {"case_id": 1, "note": "n"}, principal=p)
                self.assertEqual(out, "ran:add_case_note")
                self.assertEqual([c[0] for c in self.stub.calls], ["decide"])

    def test_unknown_halt_state_counts_as_halted(self):
        self.stub.reachable = False  # halt_status -> halted (PM-F31)
        out = self.call("add_case_note", {"case_id": 1, "note": "n", "agent_context": AGENT_CTX},
                        principal=_principal("agent", "a1"))
        self.assertIn("HALTED", out)
        self.stub.reachable = True
        self.stub.halt_status = lambda: (_ for _ in ()).throw(RuntimeError("bug"))
        out = self.call("add_case_note", {"case_id": 1, "note": "n", "agent_context": AGENT_CTX},
                        principal=_principal("agent", "a1"))
        self.assertIn("HALTED", out)
        self.assertIn("RuntimeError", out)

    def test_not_halted_agent_proceeds_to_decide(self):
        with self.assertLogs("soar_mcp.policy", level="INFO"):
            out = self.call("add_case_note", {"case_id": 1, "note": "n", "agent_context": AGENT_CTX},
                            principal=_principal("agent", "a1"))
        self.assertEqual(out, "ran:add_case_note")
        self.assertEqual([c[0] for c in self.stub.calls], ["halt_status", "decide"])

    def test_dry_runs_skip_the_halt_check(self):
        self.stub.halted = True
        out = self.call("save_playbook_layout_only", {"playbook_id": 7}, principal=_principal("agent", "a1"))
        self.assertEqual(out, "ran:save_playbook_layout_only")
        self.assertEqual(self.stub.calls, [])

    def test_halt_is_audited(self):
        self.stub.halted = True
        with self.assertLogs("soar_mcp.policy", level="WARNING") as cm:
            self.call("add_case_note", {"case_id": 1, "note": "n", "agent_context": AGENT_CTX},
                      principal=_principal("agent", "a1"))
        self.assertIn("refused=HALTED tool=add_case_note", "\n".join(cm.output))
        self.assertIn("agent_id=a1", "\n".join(cm.output))


class ClientCacheTest(unittest.TestCase):
    def setUp(self):
        sg.set_policy_client_override(None)
        sg._client_cache.clear()

    def test_client_cached_per_connection_parameters(self):
        cfg = _cfg()
        a = sg._get_client(cfg)
        b = sg._get_client(cfg)
        self.assertIs(a, b)
        cfg2 = _cfg(url="https://other.local")
        self.assertIsNot(sg._get_client(cfg2), a)

    def test_legacy_mode_has_no_client(self):
        self.assertIsNone(sg._get_client(_cfg(mode="")))

    def test_bad_url_in_service_mode_blocks(self):
        client = _FakeClient()
        with patch.dict("soar_mcp_tools._TOOL_HANDLERS", _HANDLER_PATCH):
            out = call_tool("add_case_note", {"case_id": 1, "note": "n"}, client,
                            _cfg(url="http://plain.local"), principal=_principal())
        self.assertTrue(out.startswith("⛔"))
        self.assertIn("configuration error", out)


if __name__ == "__main__":
    unittest.main()
