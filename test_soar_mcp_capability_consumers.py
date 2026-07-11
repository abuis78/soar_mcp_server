"""Tests for capability caching + consumer integration (issue #68 part 2)."""
from __future__ import annotations

import json
import unittest

import soar_mcp_capabilities as caps_mod
from soar_mcp_capabilities import explain_empty_graph, get_capabilities
from soar_mcp_config import READ_ONLY_TOOLS, McpServerConfig
from soar_mcp_tools import call_tool


class _CountingClient:
    """Healthy client with an extractable COA graph; counts probe calls."""
    def __init__(self, base="https://s/rest", nodes=3):
        self._base_url = base
        self._nodes = nodes
        self.coa_calls = 0

    def _coa_get(self, path, params=None):
        self.coa_calls += 1
        return {
            "id": 1, "current_id": 1,
            "coa_data": {
                "nodes": {str(i): {"data": {"functionName": f"n{i}", "type": "action"}}
                          for i in range(self._nodes)},
                "edges": [{"source": "0", "target": "1"}],
            },
        }, None

    def get(self, path, params=None):
        if path.startswith("playbook/"):
            return {"id": 1, "passed_validation": True, "python": "x=1\n"}, None
        return {}, None

    def get_binary(self, path, params=None):
        return b"TAR", None


class _NoGraphClient:
    def __init__(self, base="https://n/rest"):
        self._base_url = base
    def _coa_get(self, path, params=None):
        return None, "Connection error: could not reach COA endpoint."
    def get(self, path, params=None):
        return None, "Connection error."
    def get_binary(self, path, params=None):
        return None, "404"


def _cfg():
    c = McpServerConfig()
    c.enabled_tools = set(READ_ONLY_TOOLS)
    return c


class CacheTest(unittest.TestCase):
    def setUp(self):
        caps_mod._cache.clear()

    def test_get_capabilities_caches(self):
        c = _CountingClient()
        r1 = get_capabilities(c, 1)
        calls_after_first = c.coa_calls
        r2 = get_capabilities(c, 1)
        self.assertIs(r1, r2)                    # same cached object
        self.assertEqual(c.coa_calls, calls_after_first)  # no re-probe

    def test_cache_expires(self):
        c = _CountingClient()
        get_capabilities(c, 1, ttl=0.0)          # immediately stale
        first = c.coa_calls
        get_capabilities(c, 1, ttl=0.0)
        self.assertGreater(c.coa_calls, first)   # re-probed


class ExplainTest(unittest.TestCase):
    def setUp(self):
        caps_mod._cache.clear()

    def test_explain_none_when_graph_available(self):
        self.assertIsNone(explain_empty_graph(_CountingClient(), 1))

    def test_explain_finding_when_no_graph(self):
        f = explain_empty_graph(_NoGraphClient(), 1)
        self.assertIsNotNone(f)
        self.assertEqual(f["code"], "graph_unavailable")


class ConsumerTest(unittest.TestCase):
    def setUp(self):
        caps_mod._cache.clear()

    def test_healthy_nodes_no_finding(self):
        out = call_tool("list_playbook_nodes", {"playbook_id": 1}, _CountingClient(nodes=3), _cfg())
        d = json.loads(out)
        self.assertEqual(d["data"]["total_nodes_in_coa"], 3)
        self.assertEqual(d["findings"], [])
        self.assertTrue(d["ok"])

    def test_empty_graph_gets_capability_finding(self):
        out = call_tool("list_playbook_nodes", {"playbook_id": 1}, _NoGraphClient(), _cfg())
        d = json.loads(out)
        self.assertEqual(d["data"]["total_nodes_in_coa"], 0)
        self.assertTrue(any(f["code"] == "graph_unavailable" for f in d["findings"]))
        self.assertFalse(d["ok"])

    def test_empty_edges_gets_capability_finding(self):
        out = call_tool("list_playbook_edges", {"playbook_id": 1}, _NoGraphClient(), _cfg())
        d = json.loads(out)
        self.assertTrue(any(f["code"] == "graph_unavailable" for f in d["findings"]))


if __name__ == "__main__":
    unittest.main()
