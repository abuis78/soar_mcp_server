"""SPEC-MCP Phase 4.2: broker context on read calls (MCP-L04, AC-07)."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from soar_mcp_config import ALL_TOOLS, READ_ONLY_TOOLS, McpServerConfig
from soar_mcp_handler import SoarMcpRestHandler
from soar_mcp_tokens import TokenVerification
from soar_mcp_tools import TOOL_SCHEMAS, _WRITE_TOOLS


def _tv(principal_type="broker", agent_id=None, allowed_tools=None):
    return TokenVerification(valid=True, token_id="tok_b", label="broker-1", soar_user_id="svc",
                             soar_call_token="ph", allowed_tools=allowed_tools,
                             principal_type=principal_type, agent_id=agent_id)


def _cfg(max_results=50):
    cfg = McpServerConfig()
    cfg.enabled_tools = set(ALL_TOOLS)
    cfg.max_results = max_results
    return cfg


class _Calls(unittest.TestCase):
    def setUp(self):
        self.h = SoarMcpRestHandler.__new__(SoarMcpRestHandler)
        self.audit = patch.object(SoarMcpRestHandler, "_audit_tool_call")
        self.audit_mock = self.audit.start()
        self.addCleanup(self.audit.stop)

    def call(self, tv, args, tool="list_cases", cfg=None):
        with patch("soar_mcp_handler.call_tool", return_value="ok") as ct:
            res = self.h._handle_tools_call({"name": tool, "arguments": args}, object(), cfg or _cfg(), tv)
        return res, ct


class BrokerContextTest(_Calls):
    def test_broker_without_aufruf_id_refused(self):
        for args in ({}, {"broker_aufruf_id": ""}, {"broker_aufruf_id": 42}, {"broker_aufruf_id": "../x"},
                     {"broker_aufruf_id": "a" * 129}):
            with self.subTest(args=args):
                res, ct = self.call(_tv(), args)
                self.assertTrue(res.get("isError"))
                self.assertIn("broker_aufruf_id is required", res["content"][0]["text"])
                ct.assert_not_called()
                self.assertEqual(self.audit_mock.call_args.kwargs["outcome"], "denied:missing_broker_aufruf_id")

    def test_broker_with_aufruf_id_proceeds(self):
        res, ct = self.call(_tv(), {"broker_aufruf_id": "tb-2026-10-19-000231", "agent_id": "triage", "lauf_id": "r-1"})
        self.assertFalse(res.get("isError"))
        ct.assert_called_once()
        self.assertEqual(self.audit_mock.call_args.kwargs["outcome"], "ok")

    def test_optional_context_must_be_well_formed(self):
        for args in ({"broker_aufruf_id": "tb-1", "agent_id": 7}, {"broker_aufruf_id": "tb-1", "lauf_id": "r 1"}):
            with self.subTest(args=args):
                res, ct = self.call(_tv(), args)
                self.assertTrue(res.get("isError"))
                ct.assert_not_called()

    def test_other_principals_never_need_the_context(self):
        for tv in (None, _tv("mensch"), _tv("agent", "a1")):
            with self.subTest(tv=getattr(tv, "principal_type", "legacy")):
                cfg = _cfg()
                cfg.agent_read_exceptions = ["list_cases"]
                res, ct = self.call(tv, {}, cfg=cfg)
                self.assertFalse(res.get("isError"), res)
                ct.assert_called_once()

    def test_limit_capped_to_max_results_for_brokers_only(self):
        res, ct = self.call(_tv(), {"broker_aufruf_id": "tb-1", "limit": 500}, cfg=_cfg(max_results=25))
        self.assertEqual(ct.call_args.args[1]["limit"], 25)
        res, ct = self.call(_tv(), {"broker_aufruf_id": "tb-1", "limit": 10}, cfg=_cfg(max_results=25))
        self.assertEqual(ct.call_args.args[1]["limit"], 10)
        res, ct = self.call(_tv("mensch"), {"limit": 500}, cfg=_cfg(max_results=25))
        self.assertEqual(ct.call_args.args[1]["limit"], 500)  # tools clamp for humans as before
        res, ct = self.call(_tv(), {"broker_aufruf_id": "tb-1", "limit": "lots"}, cfg=_cfg(max_results=25))
        self.assertEqual(ct.call_args.args[1]["limit"], "lots")  # left to the tool's own validation

    def test_write_block_wins_before_context_check(self):
        res, ct = self.call(_tv(allowed_tools=["run_playbook"]), {}, tool="run_playbook")
        self.assertIn("not a read tool", res["content"][0]["text"])


class BrokerAuditTest(unittest.TestCase):
    def test_audit_takes_agent_id_from_broker_arguments(self):
        line = SoarMcpRestHandler._audit_identity(_tv(), {"broker_aufruf_id": "tb-9", "agent_id": "triage", "lauf_id": "r-2"})
        self.assertIn("principal=broker", line)
        self.assertIn("agent_id=triage", line)
        self.assertIn("broker_aufruf_id=tb-9", line)
        self.assertIn("lauf_id=r-2", line)
        # An agent token keeps its own agent_id; the argument never overrides it.
        line = SoarMcpRestHandler._audit_identity(_tv("agent", "a1"), {"agent_id": "spoof"})
        self.assertIn("agent_id=a1", line)
        line = SoarMcpRestHandler._audit_identity(_tv("mensch"), {"agent_id": "x"})
        self.assertIn("agent_id=-", line)


class BrokerSchemaTest(unittest.TestCase):
    def test_read_tools_document_the_context(self):
        for name in READ_ONLY_TOOLS:
            with self.subTest(tool=name):
                props = TOOL_SCHEMAS[name]["inputSchema"]["properties"]
                for key in ("broker_aufruf_id", "agent_id", "lauf_id"):
                    self.assertEqual(props[key]["type"], "string")
                self.assertNotIn("broker_aufruf_id", TOOL_SCHEMAS[name]["inputSchema"].get("required", []))

    def test_write_and_gate_tools_untouched(self):
        for name in list(_WRITE_TOOLS) + ["approve_action"]:
            self.assertNotIn("broker_aufruf_id", TOOL_SCHEMAS[name]["inputSchema"]["properties"])


if __name__ == "__main__":
    unittest.main()
