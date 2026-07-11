"""Tests for hiding unverified tools from tools/list (issue #65)."""
from __future__ import annotations

import unittest

from soar_mcp_config import McpServerConfig
from soar_mcp_handler import SoarMcpRestHandler


def _handler():
    # Bypass __init__ (which runs full request processing) — we only test one method.
    return SoarMcpRestHandler.__new__(SoarMcpRestHandler)


class HiddenToolsTest(unittest.TestCase):
    def test_layout_write_hidden_even_when_enabled(self):
        cfg = McpServerConfig()
        cfg.enabled_tools = {"list_cases", "save_playbook_layout_only"}
        result = _handler()._handle_tools_list(cfg)
        names = {t["name"] for t in result["tools"]}
        self.assertIn("list_cases", names)
        self.assertNotIn("save_playbook_layout_only", names)

    def test_other_tools_unaffected(self):
        cfg = McpServerConfig()
        cfg.enabled_tools = {"list_cases", "get_case", "detect_soar_capabilities"}
        names = {t["name"] for t in _handler()._handle_tools_list(cfg)["tools"]}
        self.assertEqual(names, {"list_cases", "get_case", "detect_soar_capabilities"})


if __name__ == "__main__":
    unittest.main()
