"""Unit tests for the policy approval store (issue #138, Phase 3). No SOAR."""
from __future__ import annotations

import os
import tempfile
import unittest

from policy.approvals import ApprovalStore


class ApprovalStoreTest(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.mkdtemp()
        self.path = os.path.join(self._dir, "pending_approvals.json")
        self.store = ApprovalStore(self.path)
        self.tool = "run_playbook"
        self.args = {"case_id": 1, "playbook_id": 25}

    # --- 1-click (single approver) ------------------------------------------

    def test_one_click_single_approver_approves(self):
        tok = self.store.issue(self.tool, self.args, needed=1)
        res = self.store.submit(tok, self.tool, self.args, "alice")
        self.assertTrue(res.approved)
        self.assertEqual((res.have, res.need), (1, 1))

    def test_one_click_token_is_single_use(self):
        tok = self.store.issue(self.tool, self.args, needed=1)
        self.assertTrue(self.store.submit(tok, self.tool, self.args, "alice").approved)
        # second use of a consumed token is invalid
        self.assertEqual(self.store.submit(tok, self.tool, self.args, "bob").status, "invalid")

    # --- 2-person (two DISTINCT approvers) ----------------------------------

    def test_two_person_needs_two_distinct(self):
        tok = self.store.issue(self.tool, self.args, needed=2)
        first = self.store.submit(tok, self.tool, self.args, "alice")
        self.assertEqual(first.status, "pending")
        self.assertEqual((first.have, first.need), (1, 2))
        second = self.store.submit(tok, self.tool, self.args, "bob")
        self.assertTrue(second.approved)
        self.assertEqual((second.have, second.need), (2, 2))

    def test_two_person_rejects_self_approval(self):
        tok = self.store.issue(self.tool, self.args, needed=2)
        self.assertEqual(self.store.submit(tok, self.tool, self.args, "alice").status, "pending")
        # same human again -> not counted, still one short
        dup = self.store.submit(tok, self.tool, self.args, "alice")
        self.assertEqual(dup.status, "duplicate")
        self.assertEqual((dup.have, dup.need), (1, 2))
        # a genuinely different second human completes it
        self.assertTrue(self.store.submit(tok, self.tool, self.args, "carol").approved)

    def test_empty_approver_is_invalid(self):
        tok = self.store.issue(self.tool, self.args, needed=1)
        self.assertEqual(self.store.submit(tok, self.tool, self.args, "").status, "invalid")
        self.assertEqual(self.store.submit(tok, self.tool, self.args, "   ").status, "invalid")

    # --- token binding / fail-safe ------------------------------------------

    def test_wrong_args_are_invalid_but_do_not_destroy_pending(self):
        tok = self.store.issue(self.tool, self.args, needed=2)
        self.store.submit(tok, self.tool, self.args, "alice")            # 1/2 recorded
        bad = self.store.submit(tok, self.tool, {"case_id": 9, "playbook_id": 9}, "bob")
        self.assertEqual(bad.status, "invalid")
        # the legitimate pending approval survived the bad-args call
        self.assertTrue(self.store.submit(tok, self.tool, self.args, "bob").approved)

    def test_unknown_token_is_invalid(self):
        self.assertEqual(
            self.store.submit("approve_nope", self.tool, self.args, "alice").status, "invalid")

    def test_expired_token_is_invalid(self):
        tok = self.store.issue(self.tool, self.args, needed=1, ttl=-1.0)
        self.assertEqual(self.store.submit(tok, self.tool, self.args, "alice").status, "invalid")

    def test_survives_new_store_instance(self):
        # file-backed: a second process (new instance, same path) sees the pending token
        tok = self.store.issue(self.tool, self.args, needed=2)
        self.store.submit(tok, self.tool, self.args, "alice")
        other = ApprovalStore(self.path)
        self.assertTrue(other.submit(tok, self.tool, self.args, "bob").approved)


if __name__ == "__main__":
    unittest.main()
