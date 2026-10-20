"""SPEC-MCP Phase 2.4: agent_context object (MCP-W07, concept OQ-12)."""

from __future__ import annotations

import json
import unittest

from policy.agent_context import (
    AGENT_CONTEXT_SCHEMA,
    INCOMPLETE_JUDGEMENT,
    INVALID_AGENT_CONTEXT,
    NO_EVIDENCE,
    describe_agent_context_error,
    lauf_id_from_arguments,
    validate_agent_context,
)
from soar_mcp_config import READ_ONLY_TOOLS
from soar_mcp_handler import SoarMcpRestHandler
from soar_mcp_tokens import TokenVerification
from soar_mcp_tools import TOOL_SCHEMAS, _WRITE_TOOLS

FULL = {
    "lauf_id": "r-8812",
    "stufe": 3,
    "domaene": "cyber",
    "tipping_off": "laut",
    "beleg_ids": ["tb-2026-10-17-000231"],
    "urteil": {
        "empfehlung": "isolate host",
        "gegenargumente": ["could be a false positive"],
        "unsicherheiten": ["no EDR telemetry for 2h"],
        "konfidenz": 0.72,
    },
}


class ValidateAgentContextTest(unittest.TestCase):
    def test_full_object_valid_for_agent(self):
        ctx, code = validate_agent_context(FULL, required=True)
        self.assertIsNone(code)
        self.assertEqual(ctx, FULL)
        self.assertEqual(describe_agent_context_error(FULL, required=True), "")

    def test_absent_is_fine_for_humans_but_no_evidence_for_agents(self):
        self.assertEqual(validate_agent_context(None, required=False), (None, None))
        ctx, code = validate_agent_context(None, required=True)
        self.assertEqual((ctx, code), (None, NO_EVIDENCE))
        self.assertIn("required", describe_agent_context_error(None, required=True))

    def test_agent_without_beleg_ids_is_no_evidence(self):
        for raw in (dict(FULL, beleg_ids=[]), {k: v for k, v in FULL.items() if k != "beleg_ids"}):
            ctx, code = validate_agent_context(raw, required=True)
            self.assertEqual((ctx, code), (None, NO_EVIDENCE))

    def test_agent_with_incomplete_urteil_is_incomplete_judgement(self):
        for missing in ("gegenargumente", "unsicherheiten", "konfidenz"):
            urteil = {k: v for k, v in FULL["urteil"].items() if k != missing}
            ctx, code = validate_agent_context(dict(FULL, urteil=urteil), required=True)
            self.assertEqual((ctx, code), (None, INCOMPLETE_JUDGEMENT), missing)
            self.assertIn(missing, describe_agent_context_error(dict(FULL, urteil=urteil), required=True))
        ctx, code = validate_agent_context({k: v for k, v in FULL.items() if k != "urteil"}, required=True)
        self.assertEqual(code, INCOMPLETE_JUDGEMENT)

    def test_human_partial_object_is_accepted(self):
        ctx, code = validate_agent_context({"lauf_id": "r-1", "stufe": 2}, required=False)
        self.assertIsNone(code)
        self.assertEqual(ctx, {"lauf_id": "r-1", "stufe": 2})

    def test_invalid_shapes(self):
        cases = [
            "not an object",
            {"unknown": 1},
            {"stufe": 5},
            {"stufe": -1},
            {"stufe": "3"},
            {"stufe": True},
            {"domaene": "space"},
            {"tipping_off": "loud"},
            {"beleg_ids": "tb-1"},
            {"beleg_ids": [1]},
            {"beleg_ids": [""]},
            {"lauf_id": ""},
            {"lauf_id": "x" * 129},
            {"urteil": "fine"},
            {"urteil": {"extra": 1}},
            {"urteil": {"konfidenz": 1.5}},
            {"urteil": {"konfidenz": "0.5"}},
            {"urteil": {"konfidenz": True}},
            {"urteil": {"gegenargumente": "none"}},
            {"urteil": {"empfehlung": "x" * 2001}},
            {"beleg_ids": ["a"] * 51},
        ]
        for raw in cases:
            with self.subTest(raw=str(raw)[:60]):
                ctx, code = validate_agent_context(raw, required=False)
                self.assertEqual((ctx, code), (None, INVALID_AGENT_CONTEXT))
                self.assertTrue(describe_agent_context_error(raw, required=False))

    def test_normalisation(self):
        ctx, _ = validate_agent_context(
            {"domaene": " Cyber ", "tipping_off": "LEISE", "lauf_id": " r-2 ",
             "urteil": {"konfidenz": 1}}, required=False)
        self.assertEqual(ctx, {"domaene": "cyber", "tipping_off": "leise", "lauf_id": "r-2",
                               "urteil": {"konfidenz": 1.0}})
        self.assertIsInstance(ctx["urteil"]["konfidenz"], float)

    def test_invalid_beats_missing_evidence_for_agents(self):
        ctx, code = validate_agent_context({"stufe": 9}, required=True)
        self.assertEqual(code, INVALID_AGENT_CONTEXT)


class SchemaAttachmentTest(unittest.TestCase):
    def test_every_write_tool_has_optional_agent_context(self):
        self.assertEqual(len(_WRITE_TOOLS), 12)
        for name in _WRITE_TOOLS:
            with self.subTest(tool=name):
                schema = TOOL_SCHEMAS[name]["inputSchema"]
                self.assertIs(schema["properties"]["agent_context"], AGENT_CONTEXT_SCHEMA)
                self.assertNotIn("agent_context", schema.get("required", []))
                self.assertEqual(schema["properties"]["freigabe_id"]["type"], "string")  # Phase 3.3
                self.assertNotIn("freigabe_id", schema.get("required", []))

    def test_read_tools_untouched(self):
        for name in READ_ONLY_TOOLS:
            if name in TOOL_SCHEMAS:
                self.assertNotIn("agent_context", TOOL_SCHEMAS[name]["inputSchema"].get("properties", {}))
                self.assertNotIn("freigabe_id", TOOL_SCHEMAS[name]["inputSchema"].get("properties", {}))

    def test_schema_is_json_serialisable_and_closed(self):
        json.dumps(AGENT_CONTEXT_SCHEMA)
        self.assertFalse(AGENT_CONTEXT_SCHEMA["additionalProperties"])
        self.assertEqual(AGENT_CONTEXT_SCHEMA["properties"]["stufe"]["maximum"], 4)
        self.assertEqual(AGENT_CONTEXT_SCHEMA["properties"]["urteil"]["properties"]["konfidenz"]["maximum"], 1)


class LaufIdAuditTest(unittest.TestCase):
    def test_lauf_id_from_arguments_prefers_agent_context(self):
        self.assertEqual(lauf_id_from_arguments({"agent_context": {"lauf_id": "ctx"}, "lauf_id": "top"}), "ctx")
        self.assertEqual(lauf_id_from_arguments({"lauf_id": "top"}), "top")
        self.assertEqual(lauf_id_from_arguments({"agent_context": {"lauf_id": " "}, "lauf_id": "top"}), "top")
        self.assertIsNone(lauf_id_from_arguments({"agent_context": "junk"}))
        self.assertIsNone(lauf_id_from_arguments(None))

    def test_audit_identity_uses_agent_context_lauf_id(self):
        tv = TokenVerification(valid=True, token_id="tok", label="l", soar_user_id="u",
                               principal_type="agent", agent_id="a1")
        line = SoarMcpRestHandler._audit_identity(tv, {"agent_context": {"lauf_id": "r-ctx"}, "lauf_id": "r-top"})
        self.assertIn("lauf_id=r-ctx", line)
        line = SoarMcpRestHandler._audit_identity(tv, {"lauf_id": "r-top"})
        self.assertIn("lauf_id=r-top", line)
        line = SoarMcpRestHandler._audit_identity(tv, {})
        self.assertIn("lauf_id=-", line)


if __name__ == "__main__":
    unittest.main()
