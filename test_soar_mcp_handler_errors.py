"""Regression coverage for MCP handler error and dry-run semantics."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from soar_mcp_config import McpServerConfig
from soar_mcp_handler import SoarMcpRestHandler


class _FakeClient:
    pass


class SoarMcpHandlerErrorsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = McpServerConfig()
        self.client = _FakeClient()
        self.handler = dict.__new__(SoarMcpRestHandler)

    def test_handler_marks_error_text_as_mcp_error(self):
        with patch("soar_mcp_handler.call_tool", return_value="Error: invalid input"):
            result = self.handler._handle_tools_call(
                {"name": "list_cases", "arguments": {}},
                self.client,
                self.cfg,
                None,
            )
        self.assertTrue(result["isError"])

        with patch("soar_mcp_handler.call_tool", return_value='{"ok": false, "errors": []}'):
            result = self.handler._handle_tools_call(
                {"name": "list_cases", "arguments": {}},
                self.client,
                self.cfg,
                None,
            )
        self.assertTrue(result["isError"])

    def test_handler_allows_disabled_layout_dry_run_preview_only(self):
        self.assertNotIn("save_playbook_layout_only", self.cfg.enabled_tools)
        with patch("soar_mcp_handler.call_tool", return_value='{"ok": true}'):
            result = self.handler._handle_tools_call(
                {
                    "name": "save_playbook_layout_only",
                    "arguments": {"playbook_id": 180, "node_positions": {"a": {"x": 1, "y": 2}}},
                },
                self.client,
                self.cfg,
                None,
            )
        self.assertFalse(result["isError"])

        denied = self.handler._handle_tools_call(
            {
                "name": "save_playbook_layout_only",
                "arguments": {
                    "playbook_id": 180,
                    "node_positions": {"a": {"x": 1, "y": 2}},
                    "dry_run": False,
                },
            },
            self.client,
            self.cfg,
            None,
        )
        self.assertTrue(denied["isError"])


if __name__ == "__main__":
    unittest.main()
