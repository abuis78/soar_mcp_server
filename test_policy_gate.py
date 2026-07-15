"""Tests for the policy gate wired into call_tool (issue #137)."""
from __future__ import annotations

import unittest

from soar_mcp_config import McpServerConfig
from soar_mcp_tools import call_tool


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

    def test_two_person_category_is_held(self):
        c = _FakeClient("Containment")
        out = call_tool("run_playbook", {"case_id": 1, "playbook_id": 1}, c, _cfg(policy=True))
        self.assertFalse(c.ran)
        self.assertIn("Approval required", out)
        self.assertIn("2 approver", out)

    def test_one_click_category_is_held(self):
        c = _FakeClient("Message Eviction")
        out = call_tool("run_playbook", {"case_id": 1, "playbook_id": 1}, c, _cfg(policy=True))
        self.assertFalse(c.ran)
        self.assertIn("1 approver", out)

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


if __name__ == "__main__":
    unittest.main()
