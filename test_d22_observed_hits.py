"""D22 (PolicyManager #16, variant A, M1): hit counts the server observes itself.

Covers the observation store, the read-tool hooks, the handler recording broker
reads under broker_aufruf_id, and the decide request built from them. The
Policy Manager rule ``beleg_inhalt`` (PM 0.6.0) is mirrored by a stub decision.
"""

from __future__ import annotations

import os
import tempfile
import time
import unittest
from unittest.mock import patch

import policy.observations as obs
import policy.service_gate as sg
from policy.client import PolicyDecision, StubPolicyClient
from policy.held_actions import HeldActionStore
from policy.observations import ObservationStore, set_observation_store_override, take_hits
from soar_mcp_config import ALL_TOOLS, McpServerConfig
from soar_mcp_handler import SoarMcpRestHandler
from soar_mcp_tokens import Principal, TokenVerification
from soar_mcp_tools import (_WRITE_TOOLS, call_tool, tool_get_case, tool_list_artifacts,
                            tool_list_case_notes, tool_list_cases, tool_search_cases)

URTEIL = {"empfehlung": "raise severity", "gegenargumente": ["x"], "unsicherheiten": ["y"], "konfidenz": 0.8}


def _cfg():
    c = McpServerConfig()
    c.enabled_tools = set(ALL_TOOLS)
    c.advisory_disclaimer = False
    c.policy_mode = "service"
    c.policy_service_url = "https://pm.local"
    return c


def _tv(kind, agent_id=None):
    return TokenVerification(valid=True, token_id="tok_" + kind, label=kind, soar_user_id="svc",
                             soar_call_token="ph", principal_type=kind, agent_id=agent_id)


def _beleg_inhalt(request: dict) -> PolicyDecision:
    """Stub of PM 0.6.0 rule beleg_inhalt (agent requests only)."""
    k = request["kontext"]
    if k["principal_type"] == "agent":
        ids = set(k.get("beleg_ids") or [])
        hit = any(isinstance(b.get("treffer"), int) and b["treffer"] >= 1 and b.get("beleg_id") in ids
                  for b in (k.get("belege") or []))
        if not hit or k.get("urteil", {}).get("datenlage") != "vollstaendig":
            return PolicyDecision(entscheidung_id="e-1", gate="APPROVE_1CLICK", freigabe_id="fg-1",
                                  begruendung=[{"regel": "beleg_inhalt", "gate": "APPROVE_1CLICK"}])
    return PolicyDecision(entscheidung_id="e-2", gate="ALLOW")


class _ReadClient:
    def __init__(self, rows):
        self.rows = rows

    def get(self, path, params=None):
        if path.startswith("container/"):
            return {"id": 5, "name": "c", "severity": "low", "status": "new", "label": "events"}, None
        if path in ("container", "artifact", "note"):
            return {"count": len(self.rows), "data": list(self.rows)}, None
        return {}, None


class _ErrClient:
    def get(self, path, params=None):
        return None, "HTTP 500"


class _TmpStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = ObservationStore(os.path.join(self.tmp.name, "observations.json"))
        set_observation_store_override(self.store)
        self.addCleanup(set_observation_store_override, None)
        obs.reset_hits()


class ObservationStoreTest(_TmpStore):
    def test_record_and_lookup(self):
        self.store.record("tb-1", 3, tool="list_cases", agent_id="triage")
        self.assertEqual(self.store.treffer_for("tb-1", "triage"), 3)
        self.assertIsNone(self.store.treffer_for("tb-unknown", "triage"))

    def test_bound_to_the_agent_named_by_the_broker(self):
        self.store.record("tb-1", 3, agent_id="triage")
        self.assertIsNone(self.store.treffer_for("tb-1", "other-agent"))
        self.store.record("tb-2", 2)  # broker named no agent -> any agent may cite it
        self.assertEqual(self.store.treffer_for("tb-2", "other-agent"), 2)

    def test_zero_is_kept_and_invalid_counts_are_ignored(self):
        self.store.record("tb-0", 0)
        self.assertEqual(self.store.treffer_for("tb-0"), 0)
        for bad in (-1, True, "3", 1.5, None):
            self.store.record("tb-bad", bad)  # type: ignore[arg-type]
        self.assertIsNone(self.store.treffer_for("tb-bad"))
        self.store.record("", 1)
        self.store.record("x" * 129, 1)
        self.assertIsNone(self.store.treffer_for(""))
        self.assertIsNone(self.store.treffer_for("x" * 129))

    def test_expired_entries_are_dropped(self):
        self.store.record("tb-1", 3)
        with patch.object(obs.time, "time", return_value=time.time() + obs.TTL_SECONDS + 1):
            self.assertIsNone(self.store.treffer_for("tb-1"))

    def test_file_never_holds_results_or_arguments(self):
        self.store.record("tb-1", 3, tool="list_cases", agent_id="triage")
        with open(os.path.join(self.tmp.name, "observations.json"), encoding="utf-8") as fh:
            raw = fh.read()
        self.assertEqual(set(__import__("json").loads(raw)["tb-1"]),
                         {"treffer", "tool", "agent_id", "observed_at", "expires_at"})

    def test_broken_file_means_no_hit(self):
        with open(os.path.join(self.tmp.name, "observations.json"), "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertIsNone(self.store.treffer_for("tb-1"))


class ReadToolHookTest(_TmpStore):
    def test_list_tools_note_rows_returned(self):
        cfg = _cfg()
        rows = [{"id": i, "name": f"r{i}", "severity": "low", "status": "new", "label": "events"} for i in range(3)]
        for fn, args in ((tool_list_cases, {}), (tool_search_cases, {"query": "x"}),
                         (tool_list_artifacts, {"case_id": 5}), (tool_list_case_notes, {"case_id": 5})):
            with self.subTest(tool=fn.__name__):
                obs.reset_hits()
                fn(_ReadClient(rows), cfg, dict(args))
                self.assertEqual(take_hits(), 3)
                obs.reset_hits()
                fn(_ReadClient([]), cfg, dict(args))
                self.assertEqual(take_hits(), 0)

    def test_get_case_notes_one_and_errors_note_nothing(self):
        cfg = _cfg()
        tool_get_case(_ReadClient([]), cfg, {"case_id": 5})
        self.assertEqual(take_hits(), 1)
        for fn, args in ((tool_list_cases, {}), (tool_get_case, {"case_id": 5}),
                         (tool_list_artifacts, {"case_id": 5})):
            obs.reset_hits()
            fn(_ErrClient(), cfg, dict(args))
            self.assertIsNone(take_hits(), fn.__name__)


class HandlerRecordingTest(_TmpStore):
    def setUp(self):
        super().setUp()
        self.h = SoarMcpRestHandler.__new__(SoarMcpRestHandler)
        for name in ("_audit_tool_call", "_audit_tool_result"):
            p = patch.object(SoarMcpRestHandler, name)
            p.start()
            self.addCleanup(p.stop)

    def _call(self, tv, args, hits=2, text="Found 2 case(s):", tool="list_cases"):
        def fake_call_tool(*_a, **_k):
            obs.note_hits(hits)
            return text
        cfg = _cfg()
        cfg.agent_read_exceptions = ["list_cases"]
        with patch("soar_mcp_handler.call_tool", side_effect=fake_call_tool):
            self.h._handle_tools_call({"name": tool, "arguments": args}, object(), cfg, tv)

    def test_broker_read_is_recorded_under_aufruf_id(self):
        self._call(_tv("broker"), {"broker_aufruf_id": "tb-9", "agent_id": "triage"})
        self.assertEqual(self.store.treffer_for("tb-9", "triage"), 2)
        self.assertIsNone(self.store.treffer_for("tb-9", "someone-else"))

    def test_non_broker_and_failed_reads_are_not_recorded(self):
        self._call(_tv("agent", "triage"), {"broker_aufruf_id": "tb-a"})
        self._call(_tv("mensch"), {"broker_aufruf_id": "tb-m"})
        self._call(_tv("broker"), {"broker_aufruf_id": "tb-e"}, text="Error listing cases: HTTP 500")
        for key in ("tb-a", "tb-m", "tb-e"):
            self.assertIsNone(self.store.treffer_for(key), key)


class DecideWithObservationsTest(_TmpStore):
    """The two acceptance cases from the D22 contract, end to end in call_tool."""

    def setUp(self):
        super().setUp()
        self.stub = StubPolicyClient(_beleg_inhalt)
        sg.set_policy_client_override(self.stub)
        self.addCleanup(sg.set_policy_client_override, None)
        sg.set_held_store_override(HeldActionStore(os.path.join(self.tmp.name, "held.json")))
        self.addCleanup(sg.set_held_store_override, None)
        hp = patch.dict("soar_mcp_tools._TOOL_HANDLERS",
                        {n: (lambda c, cfg, a, _n=n: f"ran:{_n}") for n in _WRITE_TOOLS})
        hp.start()
        self.addCleanup(hp.stop)
        self.agent = Principal.from_verification(_tv("agent", "triage"))

    def _write(self, datenlage="vollstaendig", belege=None):
        ctx = {"beleg_ids": ["tb-1"], "urteil": dict(URTEIL, datenlage=datenlage)}
        if belege is not None:
            ctx["belege"] = belege
        return call_tool("update_case_severity",
                         {"case_id": 5, "severity": "high", "agent_context": ctx},
                         _ReadClient([]), _cfg(), principal=self.agent)

    def test_read_with_zero_hits_needs_approval(self):
        self.store.record("tb-1", 0, agent_id="triage")
        out = self._write()
        self.assertTrue(out.startswith("⏸"), out)
        self.assertEqual(self.stub.calls[-1][1]["kontext"]["belege"], [{"beleg_id": "tb-1", "treffer": 0}])

    def test_read_with_hits_and_complete_data_is_not_forced_into_a_gate(self):
        self.store.record("tb-1", 4, agent_id="triage")
        self.assertEqual(self._write(), "ran:update_case_severity")
        self.assertEqual(self.stub.calls[-1][1]["kontext"]["belege"], [{"beleg_id": "tb-1", "treffer": 4}])

    def test_hits_but_incomplete_data_needs_approval(self):
        self.store.record("tb-1", 4, agent_id="triage")
        self.assertTrue(self._write(datenlage="teilweise").startswith("⏸"))

    def test_caller_reported_hits_are_never_adopted(self):
        out = self._write(belege=[{"beleg_id": "tb-1", "treffer": 99}])
        self.assertTrue(out.startswith("⏸"), out)
        self.assertEqual(self.stub.calls[-1][1]["kontext"]["belege"], [{"beleg_id": "tb-1", "treffer": None}])

    def test_hits_observed_for_another_agent_do_not_count(self):
        self.store.record("tb-1", 4, agent_id="other-agent")
        self.assertTrue(self._write().startswith("⏸"))


if __name__ == "__main__":
    unittest.main()
