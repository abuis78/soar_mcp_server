"""Policy asset/identity enrichment — Phase 4 (issue #139)."""
from __future__ import annotations

import unittest

from policy.policy_layer import PolicyLayer
from soar_mcp_config import McpServerConfig
from soar_mcp_tools import call_tool


class EnrichUnitTest(unittest.TestCase):
    def setUp(self):
        self.p = PolicyLayer()  # real policy_config.json (has asset_context)

    def test_asset_context_enabled(self):
        self.assertTrue(self.p.asset_context_enabled)

    def test_asset_tag_and_criticality(self):
        e = self.p.enrich(["DC01.corp.local"])
        self.assertIn("domain_controller", e["target_asset_tags"])
        self.assertEqual(e["asset_criticality"], 1.0)

    def test_identity_tag(self):
        e = self.p.enrich(["ceo@corp.com"])
        self.assertIn("executive", e["target_identity_tags"])
        self.assertEqual(e["asset_criticality"], 0.0)  # identity match ≠ crown-jewel asset

    def test_no_match_is_empty(self):
        e = self.p.enrich(["web-frontend-01", "8.8.8.8"])
        self.assertEqual(e["target_asset_tags"], [])
        self.assertEqual(e["target_identity_tags"], [])
        self.assertEqual(e["asset_criticality"], 0.0)

    def test_disabled_when_no_asset_context(self):
        self.assertFalse(PolicyLayer("/nonexistent.json").asset_context_enabled)


class _FakeClient:
    def __init__(self, category="Enrichment", artifacts=None, artifact_err=None):
        self._base_url = "https://s/rest"
        self._category = category
        self._artifacts = artifacts or []
        self._artifact_err = artifact_err
        self.ran = False

    def get(self, path, params=None):
        if path.startswith("playbook/"):
            return {"id": 1, "name": "PB", "category": self._category}, None
        if path == "artifact":
            if self._artifact_err:
                return None, self._artifact_err
            return {"data": self._artifacts}, None
        return {}, None

    def post(self, path, body):
        if path == "playbook_run":
            self.ran = True
            return {"playbook_run_id": 1}, None
        return {}, None


def _cfg():
    c = McpServerConfig()
    c.policy_enabled = True
    c.advisory_disclaimer = False
    return c


class EnrichmentGateTest(unittest.TestCase):
    """The target override must fire LIVE from case artifacts (#139)."""

    def test_dc_artifact_forces_two_person_on_mild_category(self):
        # Enrichment alone = ALLOW, but a domain-controller target escalates to 2-person.
        c = _FakeClient(category="Enrichment",
                        artifacts=[{"cef": {"destinationHostName": "dc01.corp"}}])
        out = call_tool("run_playbook", {"case_id": 127, "playbook_id": 1}, c, _cfg())
        self.assertIn("Approval required", out)
        self.assertIn("2 distinct approver", out)
        self.assertFalse(c.ran)

    def test_executive_identity_forces_two_person(self):
        c = _FakeClient(category="Enrichment",
                        artifacts=[{"cef": {"sourceUserName": "ceo"}}])
        out = call_tool("run_playbook", {"case_id": 127, "playbook_id": 1}, c, _cfg())
        self.assertIn("Approval required", out)
        self.assertFalse(c.ran)

    def test_no_matching_artifact_runs(self):
        c = _FakeClient(category="Enrichment",
                        artifacts=[{"cef": {"destinationHostName": "web01"}}])
        call_tool("run_playbook", {"case_id": 127, "playbook_id": 1}, c, _cfg())
        self.assertTrue(c.ran)  # ALLOW — no escalation

    def test_artifact_fetch_error_does_not_downgrade(self):
        # fail-safe: enrichment error -> no tags, base gate governs (Enrichment=ALLOW)
        c = _FakeClient(category="Enrichment", artifact_err="boom")
        call_tool("run_playbook", {"case_id": 127, "playbook_id": 1}, c, _cfg())
        self.assertTrue(c.ran)

    def test_enrichment_never_relaxes_containment(self):
        # A 2-person category with a benign target stays 2-person (no relaxation).
        c = _FakeClient(category="Containment",
                        artifacts=[{"cef": {"destinationHostName": "web01"}}])
        out = call_tool("run_playbook", {"case_id": 127, "playbook_id": 1}, c, _cfg())
        self.assertIn("2 distinct approver", out)
        self.assertFalse(c.ran)


if __name__ == "__main__":
    unittest.main()
