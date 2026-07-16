"""run_playbook by name: safe resolution before the policy gate (issue #148)."""
from __future__ import annotations

import unittest

from soar_mcp_config import McpServerConfig
from soar_mcp_tools import _resolve_playbook_id_by_name, call_tool


class _FakeClient:
    def __init__(self, playbooks, category="Enrichment"):
        self._base_url = "https://s/rest"
        self._playbooks = playbooks
        self._category = category
        self.ran = False
        self.ran_playbook_id = None

    def get(self, path, params=None):
        if path == "playbook":
            return {"data": self._playbooks, "count": len(self._playbooks)}, None
        if path.startswith("playbook/"):
            pid = int(path.split("/")[1])
            return {"id": pid, "name": "PB", "category": self._category}, None
        return {}, None

    def post(self, path, body):
        if path == "playbook_run":
            self.ran = True
            self.ran_playbook_id = body.get("playbook_id")
            return {"playbook_run_id": 99}, None
        return {}, None


def _cfg(policy=False):
    c = McpServerConfig()
    c.policy_enabled = policy
    c.advisory_disclaimer = False
    return c


class ResolveByNameTest(unittest.TestCase):
    def test_unique_exact_returns_id(self):
        c = _FakeClient([{"id": 571, "name": "Claude_policy_test"}])
        self.assertEqual(_resolve_playbook_id_by_name("Claude_policy_test", c, _cfg()), 571)

    def test_exact_is_case_insensitive(self):
        c = _FakeClient([{"id": 571, "name": "Claude_policy_test"}])
        self.assertEqual(_resolve_playbook_id_by_name("claude_POLICY_test", c, _cfg()), 571)

    def test_no_match(self):
        c = _FakeClient([])
        out = _resolve_playbook_id_by_name("nope", c, _cfg())
        self.assertIsInstance(out, str)
        self.assertIn("no playbook found", out)

    def test_substring_only_refuses_with_candidates(self):
        # server-side icontains returns a superset; no EXACT match -> refuse
        c = _FakeClient([{"id": 5, "name": "Claude_policy_test_v2"}])
        out = _resolve_playbook_id_by_name("Claude_policy_test", c, _cfg())
        self.assertIsInstance(out, str)
        self.assertIn("exactly named", out)
        self.assertIn("ID 5", out)

    def test_multiple_exact_refuses(self):
        c = _FakeClient([{"id": 1, "name": "Dup"}, {"id": 2, "name": "dup"}])
        out = _resolve_playbook_id_by_name("dup", c, _cfg())
        self.assertIsInstance(out, str)
        self.assertIn("multiple playbooks", out)
        self.assertIn("ID 1", out)
        self.assertIn("ID 2", out)


class CallToolByNameTest(unittest.TestCase):
    def test_name_resolves_and_runs(self):
        c = _FakeClient([{"id": 571, "name": "Claude_policy_test"}])
        call_tool("run_playbook", {"case_id": 1, "playbook_name": "Claude_policy_test"},
                  c, _cfg(policy=False))
        self.assertTrue(c.ran)
        self.assertEqual(c.ran_playbook_id, 571)  # resolved id reached the run

    def test_ambiguous_name_refuses_and_does_not_run(self):
        c = _FakeClient([{"id": 1, "name": "Dup"}, {"id": 2, "name": "dup"}])
        out = call_tool("run_playbook", {"case_id": 1, "playbook_name": "dup"},
                        c, _cfg(policy=False))
        self.assertIn("multiple playbooks", out)
        self.assertFalse(c.ran)

    def test_name_invocation_still_hits_policy_gate(self):
        # SECURITY: name path must NOT bypass the policy gate. Containment -> held.
        c = _FakeClient([{"id": 571, "name": "Claude_policy_test"}], category="Containment")
        out = call_tool("run_playbook", {"case_id": 1, "playbook_name": "Claude_policy_test"},
                        c, _cfg(policy=True))
        self.assertIn("Approval required", out)
        self.assertFalse(c.ran)

    def test_id_path_unchanged(self):
        c = _FakeClient([{"id": 571, "name": "Claude_policy_test"}])
        call_tool("run_playbook", {"case_id": 1, "playbook_id": 571}, c, _cfg(policy=False))
        self.assertTrue(c.ran)
        self.assertEqual(c.ran_playbook_id, 571)


if __name__ == "__main__":
    unittest.main()
