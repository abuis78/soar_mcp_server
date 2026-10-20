"""SPEC-MCP Phase 3.2: held actions for mode service (MCP-W06, OQ-16)."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import time
import unittest

from policy.held_actions import HeldAction, HeldActionStore, expiry_from_ablauf

REQUEST = {"aktion": {"art": "add_case_note", "ziel": ["case_id=1"]}, "kontext": {"principal_type": "mensch"}}


class ExpiryTest(unittest.TestCase):
    def test_iso_with_offset_and_z(self):
        self.assertEqual(expiry_from_ablauf("2026-10-17T09:20:00+02:00"), 1792221600.0)
        self.assertEqual(expiry_from_ablauf("2026-10-17T07:20:00Z"), 1792221600.0)
        self.assertEqual(expiry_from_ablauf("2026-10-17T07:20:00"), 1792221600.0)  # naive = UTC

    def test_unparsable_falls_back_to_ten_minutes(self):
        now = 1000.0
        for bad in ("", "soon", None, "2026-13-45"):
            self.assertEqual(expiry_from_ablauf(bad, now), 1600.0, bad)


class HeldActionTest(unittest.TestCase):
    def test_build_strips_gate_arguments(self):
        h = HeldAction.build("ap-1", "add_case_note",
                             {"case_id": 1, "note": "n", "approval_token": "t", "confirm_token": "c",
                              "freigabe_id": "ap-1", "agent_context": {"stufe": 1}},
                             REQUEST, gate="APPROVE_1CLICK", noetig=0, ablauf="")
        self.assertEqual(h.args, {"case_id": 1, "note": "n"})
        self.assertEqual(h.noetig, 1)
        self.assertFalse(h.expired)
        self.assertNotIn("confirm_token", json.dumps(h.__dict__))

    def test_from_entry_tolerates_junk(self):
        self.assertIsNone(HeldAction.from_entry("x"))
        self.assertIsNone(HeldAction.from_entry({"tool": "a"}))
        h = HeldAction.from_entry({"freigabe_id": "ap-1", "tool": "t", "expires_at": "oops"})
        self.assertIsNone(h)


class HeldActionStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "local", "held_actions.json")
        self.store = HeldActionStore(self.path)

    def _held(self, fid="ap-1", ablauf="", **kw):
        return HeldAction.build(fid, "add_case_note", {"case_id": 1, "note": "n", "approval_token": "t"},
                                REQUEST, entscheidung_id="pm-1", gate="APPROVE_2PERSON", noetig=2,
                                initiator="alice", principal_type="mensch", ablauf=ablauf, **kw)

    def test_put_get_remove_roundtrip(self):
        self.assertIsNone(self.store.get("ap-1"))
        self.store.put(self._held())
        got = self.store.get("ap-1")
        self.assertIsNotNone(got)
        self.assertEqual((got.tool, got.args, got.request, got.entscheidung_id, got.gate, got.noetig,
                          got.initiator, got.principal_type),
                         ("add_case_note", {"case_id": 1, "note": "n"}, REQUEST, "pm-1", "APPROVE_2PERSON", 2,
                          "alice", "mensch"))
        self.assertEqual(self.store.count(), 1)
        self.store.remove("ap-1")
        self.assertIsNone(self.store.get("ap-1"))
        self.assertEqual(self.store.count(), 0)
        self.store.remove("ap-missing")  # no error

    def test_file_is_private_and_never_holds_gate_tokens(self):
        self.store.put(self._held())
        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        self.assertEqual(mode, 0o600)
        with open(self.path, encoding="utf-8") as fh:
            raw = fh.read()
        self.assertNotIn("approval_token", raw)
        self.assertIn("ap-1", raw)

    def test_expired_entries_are_pruned(self):
        self.store.put(self._held("ap-old", ablauf="2020-01-01T00:00:00Z"))
        self.store.put(self._held("ap-new", ablauf="2099-01-01T00:00:00Z"))
        self.assertIsNone(self.store.get("ap-old"))
        self.assertIsNotNone(self.store.get("ap-new"))
        self.assertEqual(self.store.count(), 1)
        with open(self.path, encoding="utf-8") as fh:
            self.assertNotIn("ap-old", fh.read())

    def test_default_ttl_when_no_ablauf(self):
        self.store.put(self._held("ap-x"))
        got = self.store.get("ap-x")
        self.assertGreater(got.expires_at, time.time() + 500)
        self.assertLess(got.expires_at, time.time() + 700)

    def test_corrupt_file_reads_as_empty(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertIsNone(self.store.get("ap-1"))
        self.store.put(self._held())
        self.assertIsNotNone(self.store.get("ap-1"))

    def test_put_overwrites_same_id(self):
        self.store.put(self._held())
        self.store.put(HeldAction.build("ap-1", "update_case_status", {"case_id": 2}, REQUEST))
        self.assertEqual(self.store.get("ap-1").tool, "update_case_status")
        self.assertEqual(self.store.count(), 1)

    def test_survives_a_second_store_instance(self):
        """Multi-process REST handler: another instance sees the entry."""
        self.store.put(self._held())
        other = HeldActionStore(self.path)
        self.assertEqual(other.get("ap-1").initiator, "alice")


if __name__ == "__main__":
    unittest.main()
