"""Regression coverage for SOAR asset-level MCP config overrides."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from soar_mcp_config import McpConfigLoader


class SoarMcpConfigAssetOverridesTest(unittest.TestCase):
    def test_server_base_url_is_normalised(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "default").mkdir()
            (root / "local").mkdir()
            (root / "default" / "mcp.conf").write_text(
                "[server]\nbase_url = https://soar.example.com/\n", encoding="utf-8"
            )

            cfg = McpConfigLoader(root).load()

        self.assertEqual(cfg.base_url, "https://soar.example.com")
        self.assertTrue(cfg.to_summary_dict()["base_url_configured"])

    def test_server_soar_base_url_alias_is_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "default").mkdir()
            (root / "local").mkdir()
            (root / "default" / "mcp.conf").write_text(
                "[server]\nsoar_base_url = https://alias.example.com/\n", encoding="utf-8"
            )

            cfg = McpConfigLoader(root).load()

        self.assertEqual(cfg.base_url, "https://alias.example.com")

    def test_invalid_server_base_url_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "default").mkdir()
            (root / "local").mkdir()
            (root / "default" / "mcp.conf").write_text(
                "[server]\nbase_url = soar.example.com\n", encoding="utf-8"
            )

            cfg = McpConfigLoader(root).load()

        self.assertEqual(cfg.base_url, "")
        self.assertFalse(cfg.to_summary_dict()["base_url_configured"])

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

    def test_asset_base_url_override_takes_precedence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "default").mkdir()
            (root / "local").mkdir()
            (root / "default" / "mcp.conf").write_text(
                "[server]\nbase_url = https://conf.example.com\n", encoding="utf-8"
            )
            (root / "local" / "asset_overrides.json").write_text(
                json.dumps({"base_url": "https://asset.example.com/"}), encoding="utf-8"
            )

            cfg = McpConfigLoader(root).load()

        self.assertEqual(cfg.base_url, "https://asset.example.com")


if __name__ == "__main__":
    unittest.main()
