"""SPEC-MCP Phase 2.5: Policy Manager adapter for write tools in mode service
(MCP-W01..W05, W07, W09; G03/G04; AC-01, AC-02, AC-04, AC-11; OQ-8, OQ-13).

All tests run against StubPolicyClient — no network, no Policy Manager.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

import policy.service_gate as sg
from policy.client import PolicyClientError, PolicyDecision, StubPolicyClient
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

    def test_approval_gate_holds_and_never_executes(self):
        self.stub.decision = PolicyDecision(entscheidung_id="pm-10", gate="APPROVE_2PERSON",
                                            freigaben_noetig=2, freigabe_id="ap-5521",
                                            ablauf="2026-10-19T10:00:00+02:00")
        out = self.call("delete_container", {"container_id": 5, "confirm": True})
        self.assertTrue(out.startswith("⏸"))
        for needle in ("2 distinct approver", "freigabe_id=ap-5521", "entscheidung_id=pm-10", "ablauf=2026-10-19"):
            self.assertIn(needle, out)
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


class RequestShapeTest(_Base):
    def _request(self, tool, args, principal=None):
        self.call(tool, args, principal=principal)
        return self.stub.calls[-1][1]

    def test_run_playbook_request_has_category_playbook_target_and_asset_values(self):
        req = self._request("run_playbook", {"case_id": 3, "playbook_id": 7, "scope": "new"})
        self.assertEqual(req["aktion"]["art"], "run_playbook")
        self.assertEqual(req["aktion"]["kategorie"], "Enrichment")
        self.assertEqual(req["aktion"]["playbook"], "PB")
        self.assertEqual(req["aktion"]["ziel"], {"case_id": 3, "playbook_id": 7})
        self.assertEqual(req["aktion"]["parameter"], {"case_id": 3, "playbook_id": 7, "scope": "new"})
        self.assertIn("srv-fs-01", req["kontext"]["asset_werte"])
        self.assertIn("10.0.0.5", req["kontext"]["asset_werte"])
        self.assertNotIn("reversible", str(req))

    def test_initiator_for_human_agent_and_legacy(self):
        req = self._request("add_case_note", {"case_id": 1, "note": "n"})
        self.assertEqual(req["initiator"], {"principal_type": "mensch", "token_id": "tok_x",
                                            "soar_user_id": "alice", "agent_id": None, "legacy": False})
        req = self._request("add_case_note", {"case_id": 1, "note": "n", "agent_context": AGENT_CTX},
                            principal=_principal("agent", "triage"))
        self.assertEqual(req["initiator"]["principal_type"], "agent")
        self.assertEqual(req["initiator"]["agent_id"], "triage")
        self.assertEqual(req["kontext"]["agent_id"], "triage")
        req = self._request("add_case_note", {"case_id": 1, "note": "n"}, principal=_principal("legacy"))
        self.assertEqual(req["initiator"], {"principal_type": "mensch", "token_id": None,
                                            "soar_user_id": None, "agent_id": None, "legacy": True})

    def test_gate_arguments_never_sent_as_parameters(self):
        req = self._request("add_case_note", {"case_id": 1, "note": "n", "approval_token": "t",
                                              "confirm_token": "c", "freigabe_id": "ap-1",
                                              "agent_context": {"stufe": 1}})
        self.assertEqual(set(req["aktion"]["parameter"]), {"case_id", "note"})
        self.assertEqual(req["kontext"]["stufe"], 1)

    def test_agent_context_fields_land_in_kontext(self):
        req = self._request("update_case_severity", {"case_id": 1, "severity": "high", "agent_context": AGENT_CTX},
                            principal=_principal("agent", "a1"))
        for k in ("lauf_id", "stufe", "domaene", "tipping_off", "beleg_ids", "urteil"):
            self.assertEqual(req["kontext"][k], AGENT_CTX[k])
        self.assertEqual(req["kontext"]["agent_konfidenz"], 0.8)

    def test_correlation_ids_are_not_targets(self):
        req = self._request("add_case_note", {"case_id": 1, "note": "n", "lauf_id": "r", "broker_aufruf_id": "b"})
        self.assertEqual(req["aktion"]["ziel"], {"case_id": 1})

    def test_no_case_id_means_no_asset_lookup(self):
        self._request("create_container", {"name": "x", "label": "test"})
        self.assertNotIn(("get", "artifact"), self.client.calls)

    def test_enrichment_failure_still_decides(self):
        def boom(*_a):
            raise RuntimeError("soar down")
        with patch("soar_mcp_tools._collect_case_artifact_values", side_effect=boom):
            out = self.call("add_case_note", {"case_id": 1, "note": "n"})
        self.assertEqual(out, "ran:add_case_note")
        self.assertEqual(self.stub.calls[-1][1]["kontext"]["asset_werte"], [])


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
        self.assertEqual(self.stub.calls[-1][1]["initiator"]["principal_type"], "broker")


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
