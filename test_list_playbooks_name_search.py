"""list_playbooks name search + active_only default + cap hint (issue #146)."""
from __future__ import annotations

import unittest

from soar_mcp_config import McpServerConfig
from soar_mcp_tools import tool_list_playbooks


class _FakeClient:
    def __init__(self, items, count=None):
        self._items = items
        self._count = count if count is not None else len(items)
        self.last_params = None

    def get(self, path, params=None):
        self.last_params = params
        return {"data": self._items, "count": self._count}, None


def _pb(pid, name, active=False, category="none"):
    return {"id": pid, "name": name, "active": active, "category": category}


class ListPlaybooksNameSearchTest(unittest.TestCase):
    def setUp(self):
        self.cfg = McpServerConfig()

    def test_name_builds_server_side_filter(self):
        c = _FakeClient([_pb(571, "Claude_policy_test")])
        out = tool_list_playbooks(c, self.cfg, {"name": "Claude_policy_test"})
        self.assertIn("_filter_name__icontains", c.last_params)
        self.assertIn("Claude_policy_test", c.last_params["_filter_name__icontains"])
        self.assertIn("571", out)

    def test_active_only_defaults_false_shows_inactive(self):
        # PB 571 is inactive but must still be listed (runnable by ID)
        c = _FakeClient([_pb(571, "Claude_policy_test", active=False),
                         _pb(9, "Live_PB", active=True)])
        out = tool_list_playbooks(c, self.cfg, {})
        self.assertIn("571", out)
        self.assertIn("9", out)

    def test_active_only_true_still_filters(self):
        c = _FakeClient([_pb(571, "Claude_policy_test", active=False),
                         _pb(9, "Live_PB", active=True)])
        out = tool_list_playbooks(c, self.cfg, {"active_only": True})
        self.assertIn("Live_PB", out)
        self.assertNotIn("Claude_policy_test", out)

    def test_cap_hint_when_capped_and_no_name(self):
        c = _FakeClient([_pb(i, f"pb{i}") for i in range(50)], count=427)
        out = tool_list_playbooks(c, self.cfg, {})
        self.assertIn("capped", out.lower())
        self.assertIn("name=", out)

    def test_no_cap_hint_when_name_given(self):
        c = _FakeClient([_pb(571, "Claude_policy_test")], count=1)
        out = tool_list_playbooks(c, self.cfg, {"name": "Claude"})
        self.assertNotIn("capped", out.lower())

    def test_no_match_message_includes_name(self):
        c = _FakeClient([], count=0)
        out = tool_list_playbooks(c, self.cfg, {"name": "does_not_exist"})
        self.assertIn("No playbooks found", out)
        self.assertIn("does_not_exist", out)


if __name__ == "__main__":
    unittest.main()
