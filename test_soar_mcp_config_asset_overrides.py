"""Regression coverage for SOAR asset-level MCP config overrides."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from soar_mcp_config import (
    POLICY_MODE_INVALID,
    POLICY_MODE_LEGACY,
    POLICY_MODE_SERVICE,
    McpConfigLoader,
    build_posture_report,
    policy_effective_mode,
)


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


    # --- Policy Manager connection (SPEC-MCP MCP-G03, concept OQ-8) ------------

    def test_policy_mode_default_is_legacy_path(self):
        cfg = self._load_with("[policy]\nenabled = false\n", None)
        self.assertEqual(cfg.policy_mode, "")
        self.assertEqual(policy_effective_mode(cfg), POLICY_MODE_LEGACY)
        self.assertEqual(cfg.policy_timeout_s, 5.0)
        self.assertEqual(cfg.policy_service_url, "")
        self.assertNotIn("policy_mode_invalid", build_posture_report(cfg)["risk_flags"])

    def test_policy_mode_service_from_mcp_conf(self):
        cfg = self._load_with(
            "[policy]\nmode = Service\nservice_url = https://pm.local:8443\n"
            "timeout_s = 2.5\nclient_cert = /etc/pm/c.pem\nclient_key = /etc/pm/k.pem\n"
            "ca = /etc/pm/ca.pem\n", None)
        self.assertEqual(cfg.policy_mode, "service")
        self.assertEqual(policy_effective_mode(cfg), POLICY_MODE_SERVICE)
        self.assertEqual(cfg.policy_service_url, "https://pm.local:8443")
        self.assertEqual(cfg.policy_timeout_s, 2.5)
        self.assertEqual(cfg.policy_client_cert, "/etc/pm/c.pem")
        self.assertEqual(cfg.policy_client_key, "/etc/pm/k.pem")
        self.assertEqual(cfg.policy_ca, "/etc/pm/ca.pem")
        posture = build_posture_report(cfg)
        self.assertEqual(posture["policy_mode"], "service")
        self.assertTrue(posture["policy_service_url_configured"])
        self.assertTrue(posture["policy_mtls_configured"])
        self.assertNotIn("policy_mode_invalid", posture["risk_flags"])

    def test_policy_mode_service_without_url_is_invalid(self):
        cfg = self._load_with("[policy]\nmode = service\n", None)
        self.assertEqual(policy_effective_mode(cfg), POLICY_MODE_INVALID)
        posture = build_posture_report(cfg)
        self.assertEqual(posture["policy_mode"], "invalid")
        self.assertIn("policy_mode_invalid", posture["risk_flags"])

    def test_policy_mode_embedded_is_reserved_and_invalid(self):
        cfg = self._load_with(
            "[policy]\nmode = embedded\nservice_url = https://pm.local\n", None)
        self.assertEqual(policy_effective_mode(cfg), POLICY_MODE_INVALID)
        self.assertIn("policy_mode_invalid", build_posture_report(cfg)["risk_flags"])

    def test_policy_mode_unknown_value_is_invalid(self):
        cfg = self._load_with("[policy]\nmode = whatever\n", None)
        self.assertEqual(policy_effective_mode(cfg), POLICY_MODE_INVALID)

    def test_policy_connection_override_beats_mcp_conf(self):
        cfg = self._load_with(
            "[policy]\nmode = service\nservice_url = https://conf.local\ntimeout_s = 9\n",
            {"policy_mode": " Service ", "policy_service_url": "https://asset.local",
             "policy_timeout_s": "3", "policy_client_cert": "/a/c.pem",
             "policy_client_key": "/a/k.pem", "policy_ca": "/a/ca.pem"})
        self.assertEqual(cfg.policy_mode, "service")
        self.assertEqual(cfg.policy_service_url, "https://asset.local")
        self.assertEqual(cfg.policy_timeout_s, 3.0)
        self.assertEqual(cfg.policy_client_cert, "/a/c.pem")
        self.assertEqual(cfg.policy_client_key, "/a/k.pem")
        self.assertEqual(cfg.policy_ca, "/a/ca.pem")

    def test_policy_connection_absent_override_keeps_mcp_conf(self):
        cfg = self._load_with(
            "[policy]\nmode = service\nservice_url = https://conf.local\n",
            {"policy_enabled": True})
        self.assertEqual(policy_effective_mode(cfg), POLICY_MODE_SERVICE)
        self.assertEqual(cfg.policy_service_url, "https://conf.local")

    def test_policy_mode_empty_override_resets_to_legacy(self):
        cfg = self._load_with(
            "[policy]\nmode = service\nservice_url = https://conf.local\n",
            {"policy_mode": ""})
        self.assertEqual(policy_effective_mode(cfg), POLICY_MODE_LEGACY)

    def test_policy_timeout_clamped_and_junk_falls_back(self):
        cfg = self._load_with("[policy]\ntimeout_s = 999\n", None)
        self.assertEqual(cfg.policy_timeout_s, 120.0)
        cfg = self._load_with("[policy]\ntimeout_s = 0\n", None)
        self.assertEqual(cfg.policy_timeout_s, 0.5)
        cfg = self._load_with("[policy]\ntimeout_s = 4\n", {"policy_timeout_s": "abc"})
        self.assertEqual(cfg.policy_timeout_s, 5.0)
        cfg = self._load_with("[policy]\ntimeout_s = 4\n", {"policy_timeout_s": ""})
        self.assertEqual(cfg.policy_timeout_s, 4.0)

    def test_policy_mode_in_summary_without_paths(self):
        cfg = self._load_with(
            "[policy]\nmode = service\nservice_url = https://pm.local\n"
            "client_key = /etc/pm/k.pem\n", None)
        summary = cfg.to_summary_dict()
        self.assertEqual(summary["policy_mode"], "service")
        self.assertTrue(summary["policy_service_url_configured"])
        self.assertNotIn("/etc/pm/k.pem", json.dumps(summary))

    def test_policy_fields_do_not_touch_policy_enabled(self):
        cfg = self._load_with(
            "[policy]\nenabled = true\nmode = service\nservice_url = https://pm.local\n",
            {"policy_mode": ""})
        self.assertTrue(cfg.policy_enabled)
        self.assertEqual(policy_effective_mode(cfg), POLICY_MODE_LEGACY)


if __name__ == "__main__":
    unittest.main()
