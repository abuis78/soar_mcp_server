"""Regression coverage for SOAR 8.5 playbook listing behavior."""
from __future__ import annotations

import unittest

from soar_mcp_config import McpServerConfig
from soar_mcp_tools import tool_list_playbooks


class _FakePlaybookClient:
    def __init__(self) -> None:
        self.get_calls: list[tuple[str, dict | None]] = []

    def get(self, path, params=None):
        self.get_calls.append((path, params))
        if path == "playbook":
            return {
                "data": [
                    {"id": 1, "name": "Active PB", "active": True, "category": "response"},
                    {"id": 2, "name": "Inactive PB", "active": False, "category": "response"},
                ],
                "count": 2,
            }, None
        return {}, None


class Soar85ListPlaybooksTest(unittest.TestCase):
    def test_list_playbooks_filters_active_locally(self):
        cfg = McpServerConfig()
        cfg.advisory_disclaimer = False
        client = _FakePlaybookClient()

        out = tool_list_playbooks(client, cfg, {"active_only": True})

        self.assertIn("Active PB", out)
        self.assertNotIn("Inactive PB", out)
        self.assertEqual(client.get_calls[0], ("playbook", {"page_size": 50}))


if __name__ == "__main__":
    unittest.main()
