"""Tests for the capability detection layer (issue #68).

Shapes are grounded in real observations from SOAR 8.5.0.248:
  - /coa/playbooks/{id} returns node_count and an extractable graph,
  - the REST record carries a python payload ("rest_python"),
  - the export archive is available.
"""
from __future__ import annotations

import json
import unittest

from soar_mcp_capabilities import _coa_data_has_nodes, detect_capabilities
from soar_mcp_config import READ_ONLY_TOOLS, McpServerConfig
from soar_mcp_tools import call_tool


class _Fake85Client:
    """Mimics the verified 8.5.0.248 behavior after the base_url fix."""
    def __init__(self, coa_nodes=6, rest_python=True, export=True):
        self._coa_nodes = coa_nodes
        self._rest_python = rest_python
        self._export = export

    def _coa_get(self, path, params=None):
        return {"id": 1, "node_count": self._coa_nodes,
                "coa_data": {"nodes": {str(i): {} for i in range(self._coa_nodes)}}}, None

    def get(self, path, params=None):
        if path.startswith("playbook/"):
            rec = {"id": 1, "passed_validation": True}
            if self._rest_python:
                rec["python"] = "def on_start(c):\n    pass\n"
            return rec, None
        if path == "playbook":
            return {"data": [{"id": 1}]}, None
        return {}, None

    def get_binary(self, path, params=None):
        return (b"TARBYTES", None) if self._export else (None, "404")


class ShapeExtractionTest(unittest.TestCase):
    def test_dict_nodes(self):
        ok, n = _coa_data_has_nodes({"coa_data": {"nodes": {"0": {}, "1": {}}}})
        self.assertTrue(ok)
        self.assertEqual(n, 2)

    def test_count_only(self):
        ok, n = _coa_data_has_nodes({"node_count": 6})
        self.assertTrue(ok)
        self.assertEqual(n, 6)

    def test_empty(self):
        ok, n = _coa_data_has_nodes({"foo": "bar"})
        self.assertFalse(ok)


class DetectCapabilitiesTest(unittest.TestCase):
    def test_full_85_profile(self):
        r = detect_capabilities(_Fake85Client(), 1)
        self.assertTrue(r.coa_endpoint_available)
        self.assertTrue(r.coa_graph_extractable)
        self.assertEqual(r.node_count, 6)
        self.assertEqual(r.python_source, "rest_python")
        self.assertTrue(r.export_fallback_available)
        self.assertEqual(r.validation_method, "passed_validation_flag")

    def test_export_only_python_fallback(self):
        r = detect_capabilities(_Fake85Client(rest_python=False), 1)
        self.assertEqual(r.python_source, "export_archive")

    def test_tool_registered_read_only(self):
        from soar_mcp_tools import TOOL_SCHEMAS, _TOOL_HANDLERS
        self.assertIn("detect_soar_capabilities", TOOL_SCHEMAS)
        self.assertIn("detect_soar_capabilities", _TOOL_HANDLERS)
        self.assertIn("detect_soar_capabilities", READ_ONLY_TOOLS)

    def test_tool_json_envelope(self):
        cfg = McpServerConfig()
        cfg.enabled_tools = set(READ_ONLY_TOOLS)
        out = call_tool("detect_soar_capabilities",
                        {"playbook_id": 1, "output_format": "json"}, _Fake85Client(), cfg)
        d = json.loads(out)
        self.assertTrue(d["ok"])
        self.assertEqual(d["data"]["python_source"], "rest_python")


if __name__ == "__main__":
    unittest.main()
