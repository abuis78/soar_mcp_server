"""Regression coverage for SOAR asset-level MCP config overrides."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from soar_mcp_config import McpConfigLoader


class SoarMcpConfigAssetOverridesTest(unittest.TestCase):
    def test_ssl_verify_asset_override_is_applied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "default").mkdir()
            (root / "local").mkdir()
            (root / "default" / "mcp.conf").write_text(
                "[server]\nssl_verify = true\n", encoding="utf-8"
            )
            (root / "local" / "asset_overrides.json").write_text(
                json.dumps({"ssl_verify": False}), encoding="utf-8"
            )

            cfg = McpConfigLoader(root).load()

        self.assertFalse(cfg.ssl_verify)

    def _load_with(self, mcp_conf: str, overrides: dict | None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "default").mkdir()
            (root / "local").mkdir()
            (root / "default" / "mcp.conf").write_text(mcp_conf, encoding="utf-8")
            if overrides is not None:
                (root / "local" / "asset_overrides.json").write_text(
                    json.dumps(overrides), encoding="utf-8")
            return McpConfigLoader(root).load()

    def test_policy_enabled_override_true_beats_mcp_conf_false(self):
        cfg = self._load_with("[policy]\nenabled = false\n", {"policy_enabled": True})
        self.assertTrue(cfg.policy_enabled)   # UI checkbox wins (#144)

    def test_policy_enabled_override_false_beats_mcp_conf_true(self):
        cfg = self._load_with("[policy]\nenabled = true\n", {"policy_enabled": False})
        self.assertFalse(cfg.policy_enabled)

    def test_policy_enabled_absent_override_keeps_mcp_conf(self):
        # None / key absent -> fall back to the mcp.conf [policy] value
        cfg = self._load_with("[policy]\nenabled = true\n", {"ssl_verify": True})
        self.assertTrue(cfg.policy_enabled)
        cfg2 = self._load_with("[policy]\nenabled = true\n", {"policy_enabled": None})
        self.assertTrue(cfg2.policy_enabled)

    # ── agent_read_exceptions (SPEC-MCP MCP-L02) ──────────────────────────────

    def test_agent_read_exceptions_default_empty(self):
        cfg = self._load_with("[policy]\nenabled = false\n", None)
        self.assertEqual(cfg.agent_read_exceptions, [])

    def test_agent_read_exceptions_from_mcp_conf(self):
        cfg = self._load_with(
            "[policy]\nagent_read_exceptions = get_soar_info, list_playbooks\n", None)
        self.assertEqual(cfg.agent_read_exceptions, ["get_soar_info", "list_playbooks"])

    def test_agent_read_exceptions_override_beats_mcp_conf(self):
        cfg = self._load_with(
            "[policy]\nagent_read_exceptions = get_soar_info\n",
            {"agent_read_exceptions": "list_playbooks"})
        self.assertEqual(cfg.agent_read_exceptions, ["list_playbooks"])

    def test_agent_read_exceptions_empty_override_means_none(self):
        cfg = self._load_with(
            "[policy]\nagent_read_exceptions = get_soar_info\n",
            {"agent_read_exceptions": ""})
        self.assertEqual(cfg.agent_read_exceptions, [])

    def test_agent_read_exceptions_absent_override_keeps_mcp_conf(self):
        cfg = self._load_with(
            "[policy]\nagent_read_exceptions = get_soar_info\n",
            {"agent_read_exceptions": None})
        self.assertEqual(cfg.agent_read_exceptions, ["get_soar_info"])

    def test_agent_read_exceptions_drops_write_and_unknown_tools(self):
        # Fail-safe: a write tool or a typo must never widen what an agent may call.
        cfg = self._load_with(
            "[policy]\nenabled = false\n",
            {"agent_read_exceptions": "run_playbook, get_soar_info, nope, get_soar_info"})
        self.assertEqual(cfg.agent_read_exceptions, ["get_soar_info"])

    def test_agent_read_exceptions_in_summary(self):
        cfg = self._load_with("[policy]\nenabled = false\n",
                              {"agent_read_exceptions": "get_soar_info"})
        self.assertEqual(cfg.to_summary_dict()["agent_read_exceptions"], ["get_soar_info"])


if __name__ == "__main__":
    unittest.main()
