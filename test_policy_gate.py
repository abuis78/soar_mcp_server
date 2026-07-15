"""Tests for the policy gate wired into call_tool (issues #137, #138)."""
from __future__ import annotations

import os
import re
import tempfile
import unittest

import soar_mcp_tools
from policy.approvals import ApprovalStore
from soar_mcp_config import McpServerConfig
from soar_mcp_tools import call_tool

_TOKEN_RE = re.compile(r'approval_token\s*=\s*"([^"]+)"')


class _FakeClient:
    """Returns a playbook with a given category; records whether run happened."""
    def __init__(self, category="Enrichment"):
        self._base_url = "https://s/rest"
        self._category = category
        self.ran = False

    def get(self, path, params=None):
        if path.startswith("playbook/"):
            return {"id": 1, "name": "PB", "category": self._category}, None
        return {}, None

    def post(self, path, body):
        if path == "playbook_run":
            self.ran = True
            return {"playbook_run_id": 99}, None
        return {}, None


def _cfg(policy=False):
    c = McpServerConfig()
    c.policy_enabled = policy
    c.advisory_disclaimer = False
    return c


class PolicyGateTest(unittest.TestCase):
    def test_policy_disabled_runs_normally(self):
        c = _FakeClient("Containment")  # would be 2-person, but policy is off
        call_tool("run_playbook", {"case_id": 1, "playbook_id": 1}, c, _cfg(policy=False))
        self.assertTrue(c.ran)

    def test_allow_category_runs(self):
        c = _FakeClient("Enrichment")
        call_tool("run_playbook", {"case_id": 1, "playbook_id": 1}, c, _cfg(policy=True))
        self.assertTrue(c.ran)

    def test_two_person_no_scoped_identity_is_held(self):
        # actor_id None (legacy token) -> no accountable approver -> fail-safe HOLD
        c = _FakeClient("Containment")
        out = call_tool("run_playbook", {"case_id": 1, "playbook_id": 1}, c, _cfg(policy=True))
        self.assertFalse(c.ran)
        self.assertIn("Approval required", out)
        self.assertIn("2 distinct approver", out)
        self.assertIn("not a scoped token", out)

    def test_one_click_no_scoped_identity_is_held(self):
        c = _FakeClient("Message Eviction")
        out = call_tool("run_playbook", {"case_id": 1, "playbook_id": 1}, c, _cfg(policy=True))
        self.assertFalse(c.ran)
        self.assertIn("1 distinct approver", out)

    def test_unknown_category_held_never_runs(self):
        # fail-safe: unknown category -> default_gate (2-person) -> held
        c = _FakeClient("ZzzTotallyUnknownCategory")
        out = call_tool("run_playbook", {"case_id": 1, "playbook_id": 1}, c, _cfg(policy=True))
        self.assertFalse(c.ran)
        self.assertIn("Approval required", out)

    def test_other_write_tool_not_policy_gated(self):
        # policy only guards run_playbook (D2). A different tool is untouched by it.
        c = _FakeClient("Enrichment")
        cfg = _cfg(policy=True)
        cfg.enabled_tools = {"get_soar_info"}
        # get_soar_info would call client.get('version'); our fake returns {} -> ok-ish.
        out = call_tool("get_soar_info", {}, c, cfg)
        self.assertNotIn("Approval required", out)


class PolicyApprovalFlowTest(unittest.TestCase):
    """End-to-end approval flow through call_tool with scoped-token identities (#138)."""

    def setUp(self):
        self._dir = tempfile.mkdtemp()
        # isolate the module-level approval store to a temp file
        self._saved = soar_mcp_tools._approval_store
        soar_mcp_tools._approval_store = ApprovalStore(
            os.path.join(self._dir, "pending_approvals.json"))
        self.args = {"case_id": 1, "playbook_id": 1}

    def tearDown(self):
        soar_mcp_tools._approval_store = self._saved

    def _issue_token(self, client, actor):
        out = call_tool("run_playbook", dict(self.args), client, _cfg(policy=True), actor_id=actor)
        m = _TOKEN_RE.search(out)
        self.assertIsNotNone(m, f"no approval_token in: {out!r}")
        return m.group(1)

    def test_two_person_two_distinct_approvers_execute(self):
        c = _FakeClient("Containment")
        tok = self._issue_token(c, "alice")
        a = dict(self.args, approval_token=tok)
        out1 = call_tool("run_playbook", a, c, _cfg(policy=True), actor_id="alice")
        self.assertIn("1/2", out1)
        self.assertFalse(c.ran)
        out2 = call_tool("run_playbook", a, c, _cfg(policy=True), actor_id="bob")
        self.assertTrue(c.ran)  # two distinct approvers -> executes

    def test_two_person_self_approval_blocked(self):
        c = _FakeClient("Containment")
        tok = self._issue_token(c, "alice")
        a = dict(self.args, approval_token=tok)
        call_tool("run_playbook", a, c, _cfg(policy=True), actor_id="alice")
        out = call_tool("run_playbook", a, c, _cfg(policy=True), actor_id="alice")
        self.assertIn("already approved", out)
        self.assertFalse(c.ran)

    def test_one_click_single_approver_executes(self):
        c = _FakeClient("Message Eviction")
        tok = self._issue_token(c, "alice")
        a = dict(self.args, approval_token=tok)
        call_tool("run_playbook", a, c, _cfg(policy=True), actor_id="alice")
        self.assertTrue(c.ran)

    def test_invalid_token_does_not_execute(self):
        c = _FakeClient("Containment")
        a = dict(self.args, approval_token="approve_bogus")
        out = call_tool("run_playbook", a, c, _cfg(policy=True), actor_id="alice")
        self.assertIn("Invalid or expired", out)
        self.assertFalse(c.ran)


if __name__ == "__main__":
    unittest.main()
