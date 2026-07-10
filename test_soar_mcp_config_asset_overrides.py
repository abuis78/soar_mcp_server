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


if __name__ == "__main__":
    unittest.main()
