"""Tests for the Policy Layer decision logic (issue #136). Pure logic, no SOAR."""
from __future__ import annotations

import unittest

from policy.policy_layer import ActionContext, Gate, PolicyLayer


class PolicyLayerTest(unittest.TestCase):
    def setUp(self):
        self.policy = PolicyLayer()  # loads policy/policy_config.json

    # --- Spec §7 acceptance cases -------------------------------------------

    def test_enrichment_is_autonomous(self):
        d = self.policy.evaluate(ActionContext(1, "VT_Enrich", "Enrichment", agent_confidence=0.9))
        self.assertIs(d.gate, Gate.ALLOW)

    def test_host_isolation_needs_two(self):
        d = self.policy.evaluate(ActionContext(25, "CS_Isolation", "Containment", reversible=False))
        self.assertIs(d.gate, Gate.APPROVE_2PERSON)

    def test_unknown_category_fails_safe(self):
        d = self.policy.evaluate(ActionContext(999, "X", "TotallyNewCategory"))
        self.assertIs(d.gate, Gate.APPROVE_2PERSON)   # = default_gate, never ALLOW
        self.assertNotEqual(d.gate, Gate.ALLOW)

    def test_low_confidence_escalates_enrichment(self):
        d = self.policy.evaluate(ActionContext(1, "E", "Enrichment",
                                               agent_confidence=0.0, asset_criticality=1.0))
        self.assertGreaterEqual(d.gate, Gate.APPROVE_1CLICK)

    def test_exec_target_forces_two(self):
        d = self.policy.evaluate(ActionContext(6, "AD_Enable", "Enable Account",
                                               target_identity_tags=["executive"]))
        self.assertIs(d.gate, Gate.APPROVE_2PERSON)   # override beats mild category

    # --- Additional guardrails ----------------------------------------------

    def test_risk_only_escalates_never_relaxes(self):
        # A 2-person category stays 2-person even with perfect confidence / low crit.
        d = self.policy.evaluate(ActionContext(2, "Block", "Containment",
                                               reversible=False, agent_confidence=1.0,
                                               asset_criticality=0.0))
        self.assertIs(d.gate, Gate.APPROVE_2PERSON)

    def test_message_eviction_is_one_click(self):
        d = self.policy.evaluate(ActionContext(3, "Evict", "Message Eviction"))
        self.assertIs(d.gate, Gate.APPROVE_1CLICK)

    def test_message_restoration_is_allow(self):
        d = self.policy.evaluate(ActionContext(4, "Restore", "Message Restoration"))
        self.assertIs(d.gate, Gate.ALLOW)

    def test_needed_approvers(self):
        self.assertEqual(self.policy.evaluate(
            ActionContext(1, "E", "Enrichment")).needed_approvers, 0)
        self.assertEqual(self.policy.evaluate(
            ActionContext(3, "Evict", "Message Eviction")).needed_approvers, 1)
        self.assertEqual(self.policy.evaluate(
            ActionContext(25, "Iso", "Containment")).needed_approvers, 2)

    def test_category_reversibility_from_config(self):
        self.assertFalse(self.policy.category_is_reversible("Containment"))
        self.assertTrue(self.policy.category_is_reversible("Enrichment"))

    def test_missing_config_fails_safe_to_deny(self):
        p = PolicyLayer("/nonexistent/policy_config.json")
        d = p.evaluate(ActionContext(1, "E", "Enrichment"))
        self.assertIs(d.gate, Gate.DENY)   # no config -> default DENY, never ALLOW

    def test_decision_to_dict_has_no_surprises(self):
        d = self.policy.evaluate(ActionContext(1, "VT", "Enrichment"))
        j = d.to_dict()
        self.assertEqual(j["gate"], "ALLOW")
        self.assertIn("risk_score", j)
        self.assertEqual(j["needed_approvers"], 0)


if __name__ == "__main__":
    unittest.main()
