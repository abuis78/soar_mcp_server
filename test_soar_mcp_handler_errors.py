"""Regression coverage for MCP handler error and dry-run semantics."""
from __future__ import annotations

import json
import sys
import types
import unittest
from unittest.mock import patch

from soar_mcp_config import McpServerConfig
from soar_mcp_handler import SoarMcpRestHandler


class _FakeClient:
    pass


class _FakeRequest:
    method = "POST"
    META = {"HTTP_PH_AUTH_TOKEN": "soar-token"}

    def __init__(self, payload: dict) -> None:
        self.body = json.dumps(payload).encode("utf-8")


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

    def test_extract_base_url_prefers_phantom_rest(self):
        phantom_mod = types.ModuleType("phantom")
        rest_mod = types.ModuleType("phantom.rest")
        rest_mod.get_phantom_base_url = lambda: "https://system.example.com/"
        phantom_mod.rest = rest_mod

        cfg = McpServerConfig(base_url="https://configured.example.com")
        with patch.dict(sys.modules, {"phantom": phantom_mod, "phantom.rest": rest_mod}):
            self.assertEqual(
                self.handler._extract_base_url(None, cfg),
                "https://system.example.com",
            )

    def test_extract_base_url_uses_configured_fallback(self):
        cfg = McpServerConfig(base_url="https://configured.example.com")
        with patch.dict(sys.modules, {"phantom": None, "phantom.rest": None}):
            self.assertEqual(
                self.handler._extract_base_url(None, cfg),
                "https://configured.example.com",
            )

    def test_extract_base_url_fails_closed_without_trusted_source(self):
        with patch.dict(sys.modules, {"phantom": None, "phantom.rest": None}):
            self.assertEqual(self.handler._extract_base_url(None, McpServerConfig()), "")

    def test_tools_call_without_base_url_returns_clear_mcp_error(self):
        cfg = McpServerConfig()
        request = _FakeRequest(
            {
                "jsonrpc": "2.0",
                "id": 93,
                "method": "tools/call",
                "params": {"name": "get_soar_info", "arguments": {}},
            }
        )

        with (
            patch("soar_mcp_handler.get_config", return_value=cfg),
            patch.dict(sys.modules, {"phantom": None, "phantom.rest": None}),
            patch("soar_mcp_handler.SoarApiClient") as api_client,
        ):
            result = self.handler._process(request, ["asset"])

        api_client.assert_not_called()
        self.assertEqual(result["id"], 93)
        self.assertIn("Unable to resolve SOAR base URL", result["error"]["message"])


if __name__ == "__main__":
    unittest.main()
