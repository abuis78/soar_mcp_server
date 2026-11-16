"""list_apps reports the installed app version per app."""
from __future__ import annotations

import unittest

from soar_mcp_config import McpServerConfig
from soar_mcp_tools import TOOL_SCHEMAS, tool_list_apps


class _FakeClient:
    def __init__(self, items):
        self._items = items

    def get(self, path, params=None):
        return {"data": self._items, "count": len(self._items)}, None


def _app(aid, name, **extra):
    return {"id": aid, "name": name, "product_name": name, **extra}


class ListAppsVersionTest(unittest.TestCase):
    def setUp(self):
        self.cfg = McpServerConfig()

    def test_app_version_shown(self):
        c = _FakeClient([_app(371, "SOAR Agent Runtime", app_version="2.2.1")])
        out = tool_list_apps(c, self.cfg, {"name_contains": "agent runtime"})
        self.assertIn("ID: 371 | SOAR Agent Runtime | Version: 2.2.1", out)

    def test_falls_back_to_version_field(self):
        c = _FakeClient([_app(5, "Other", version="1.0.3")])
        out = tool_list_apps(c, self.cfg, {})
        self.assertIn("Version: 1.0.3", out)

    def test_missing_version_is_unknown(self):
        c = _FakeClient([_app(6, "NoVersion")])
        out = tool_list_apps(c, self.cfg, {})
        self.assertIn("Version: unknown", out)

    def test_description_mentions_version(self):
        self.assertIn("app version", TOOL_SCHEMAS["list_apps"]["description"])


if __name__ == "__main__":
    unittest.main()
