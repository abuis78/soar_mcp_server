"""Regression coverage for SOAR 8.5 COA graph and summary behavior."""
from __future__ import annotations

import json
import unittest

from soar_mcp_config import McpServerConfig
from soar_mcp_tools import (
    _get_coa_nodes_edges,
    _resolve_current_id,
    tool_get_playbook_coa_summary,
)


class _FakeCoaClient:
    def __init__(self) -> None:
        self.coa = {
            "id": 180,
            "current_id": 180,
            "playbook_trigger": "artifact_created",
            "coa_data": {
                "nodes": {
                    "0": {
                        "id": "0",
                        "x": 10,
                        "y": 20,
                        "data": {"type": "code", "functionName": "do_work"},
                    }
                },
                "edges": [],
            },
        }

    def get(self, path, params=None):
        if path == "playbook/180":
            return {
                "id": 180,
                "name": "Quarantine",
                "version": 9,
                "playbook_trigger": "artifact_created",
                "passed_validation": True,
            }, None
        return {}, None

    def _coa_get(self, path, params=None):
        return self.coa, None

    def get_binary(self, path, params=None):
        return b"", None


class _StaleCoaClient:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def _coa_get(self, path, params=None):
        self.calls.append(path)
        if path == "playbooks/172":
            return {"id": 172, "current_id": 180, "coa_data": {"nodes": {"old": {}}}}, None
        if path == "playbooks/180":
            return {"id": 180, "current_id": 180, "coa_data": {"nodes": {"current": {}}}}, None
        return {}, None


class Soar85CoaSummaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg = McpServerConfig()
        self.cfg.advisory_disclaimer = False

    def test_coa_data_shape_is_normalized(self):
        client = _FakeCoaClient()
        nodes, edges = _get_coa_nodes_edges(client.coa)
        self.assertEqual(len(nodes), 1)
        self.assertEqual(len(edges), 0)
        self.assertEqual(nodes[0]["functionName"], "do_work")
        self.assertEqual(nodes[0]["x"], 10)

    def test_resolve_current_id_refetches_current_payload(self):
        client = _StaleCoaClient()
        current_id, coa_data, err = _resolve_current_id(client, 172)
        self.assertIsNone(err)
        self.assertEqual(current_id, 180)
        self.assertEqual(coa_data["id"], 180)
        self.assertEqual(client.calls, ["playbooks/172", "playbooks/180"])

    def test_coa_summary_reads_playbook_trigger(self):
        client = _FakeCoaClient()
        data = json.loads(tool_get_playbook_coa_summary(client, self.cfg, {"playbook_id": 180}))
        self.assertEqual(data["data"]["trigger"], "artifact_created")
        self.assertEqual(data["data"]["node_count"], 1)


if __name__ == "__main__":
    unittest.main()
