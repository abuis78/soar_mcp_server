"""Unit tests for soar_mcp_tokens.TokenStore.

Run from inside the phantom_soar_mcp_server/ directory:
    python3 -m unittest test_soar_mcp_tokens -v
"""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from soar_mcp_tokens import (PRINCIPAL_HUMAN, TokenStore, broker_allowed_tools, normalise_principal,
                             sanitise_args_for_audit)
from soar_mcp_config import McpServerConfig, ALL_TOOLS, READ_ONLY_TOOLS


class TokenStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store_path = Path(self._tmp.name) / "mcp_tokens.json"
        TokenStore._instances.clear()  # reset singleton
        self.store = TokenStore.for_path(self.store_path)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_mint_and_verify(self):
        m = self.store.mint(label="alice", soar_user_id="alice",
                            soar_call_token="ph_alice", lifetime_days=1)
        self.assertTrue(m.raw_token.startswith("soarmcp_"))
        v = self.store.verify(m.raw_token)
        self.assertIsNotNone(v)
        self.assertTrue(v.valid)
        self.assertEqual(v.soar_user_id, "alice")
        self.assertEqual(v.soar_call_token, "ph_alice")
        self.assertEqual(v.allowed_tools, None)

    def test_unknown_token_returns_none(self):
        v = self.store.verify("not-our-format-at-all")
        self.assertIsNone(v)

    def test_revoked_token_rejected(self):
        m = self.store.mint(label="bob", soar_user_id="bob",
                            soar_call_token="ph_bob", lifetime_days=1)
        self.assertTrue(self.store.revoke(m.id))
        v = self.store.verify(m.raw_token)
        self.assertFalse(v.valid)
        self.assertEqual(v.reason, "revoked")

    def test_expired_token_rejected(self):
        m = self.store.mint(label="carol", soar_user_id="carol",
                            soar_call_token="ph_carol", lifetime_days=1)
        state = self.store._load()
        for e in state.tokens:
            if e["id"] == m.id:
                e["expires_at"] = int(time.time()) - 10
        self.store._save(state)
        self.store._state = None
        v = self.store.verify(m.raw_token)
        self.assertFalse(v.valid)
        self.assertEqual(v.reason, "expired")

    def test_allowed_tools_scoping(self):
        m = self.store.mint(label="dave", soar_user_id="dave",
                            soar_call_token="ph_dave",
                            allowed_tools=["list_cases", "get_case"])
        v = self.store.verify(m.raw_token)
        self.assertEqual(set(v.allowed_tools), {"list_cases", "get_case"})

    def test_rate_limit(self):
        m = self.store.mint(label="erin", soar_user_id="erin",
                            soar_call_token="ph_erin")
        for _ in range(3):
            v = self.store.verify(m.raw_token, rate_limit=3)
            self.assertTrue(v.valid)
        v = self.store.verify(m.raw_token, rate_limit=3)
        self.assertFalse(v.valid)
        self.assertEqual(v.reason, "rate_limited")

    def test_list_excludes_revoked_by_default(self):
        m1 = self.store.mint(label="t1", soar_user_id="u", soar_call_token="t")
        m2 = self.store.mint(label="t2", soar_user_id="u", soar_call_token="t")
        self.store.revoke(m1.id)
        active = self.store.list()
        self.assertEqual([t.id for t in active], [m2.id])
        all_ = self.store.list(include_revoked=True)
        self.assertEqual({t.id for t in all_}, {m1.id, m2.id})

    def test_persistence_across_instances(self):
        m = self.store.mint(label="persist", soar_user_id="p", soar_call_token="t")
        TokenStore._instances.clear()
        fresh = TokenStore.for_path(self.store_path)
        v = fresh.verify(m.raw_token)
        self.assertTrue(v.valid)
        self.assertEqual(v.soar_user_id, "p")

    def test_file_permissions_restricted(self):
        self.store.mint(label="perm", soar_user_id="p", soar_call_token="t")
        mode = os.stat(self.store_path).st_mode & 0o777
        self.assertEqual(mode, 0o600)


class PrincipalTypeTest(unittest.TestCase):
    """SPEC-MCP MCP-G01: every scoped token carries a principal_type."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store_path = Path(self._tmp.name) / "mcp_tokens.json"
        TokenStore._instances.clear()
        self.store = TokenStore.for_path(self.store_path)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _mint(self, **kw):
        base = dict(label="t", soar_user_id="u", soar_call_token="ph_u", lifetime_days=1)
        base.update(kw)
        return self.store.mint(**base)

    def test_default_is_mensch(self):
        m = self._mint()
        self.assertEqual(m.principal_type, PRINCIPAL_HUMAN)
        self.assertIsNone(m.agent_id)
        v = self.store.verify(m.raw_token)
        self.assertEqual(v.principal_type, PRINCIPAL_HUMAN)
        self.assertIsNone(v.agent_id)

    def test_agent_round_trip(self):
        m = self._mint(principal_type="agent", agent_id="triage_agent")
        self.assertEqual(m.principal_type, "agent")
        self.assertEqual(m.agent_id, "triage_agent")
        v = self.store.verify(m.raw_token)
        self.assertEqual((v.principal_type, v.agent_id), ("agent", "triage_agent"))
        summary = self.store.list()[0]
        self.assertEqual((summary.principal_type, summary.agent_id), ("agent", "triage_agent"))

    def test_broker_round_trip_drops_agent_id(self):
        m = self._mint(principal_type="broker", agent_id="ignored", allowed_tools=["get_case"])
        v = self.store.verify(m.raw_token)
        self.assertEqual(v.principal_type, "broker")
        self.assertIsNone(v.agent_id)
        self.assertEqual(v.allowed_tools, ["get_case"])

    # --- SPEC-MCP Phase 4.1: broker tokens read only (MCP-L03/L05, AC-07) ----

    def test_broker_allow_list_is_cut_to_read_tools(self):
        m = self._mint(principal_type="broker",
                       allowed_tools=["get_case", "run_playbook", "approve_action", "get_case", " list_cases "])
        self.assertEqual(m.allowed_tools, ["get_case", "list_cases"])
        v = self.store.verify(m.raw_token)
        self.assertEqual(v.allowed_tools, ["get_case", "list_cases"])

    def test_broker_without_read_tools_rejected(self):
        for allowed in (None, [], ["run_playbook"], ["approve_action", "add_case_note"]):
            with self.subTest(allowed=allowed):
                with self.assertRaises(ValueError) as cm:
                    self._mint(principal_type="broker", allowed_tools=allowed)
                self.assertIn("broker", str(cm.exception))
        self.assertEqual(self.store.list(), [])

    def test_broker_allowed_tools_helper(self):
        self.assertEqual(broker_allowed_tools(["list_cases", "add_case_note"]), ["list_cases"])
        self.assertTrue(set(broker_allowed_tools(list(ALL_TOOLS))) <= READ_ONLY_TOOLS)
        self.assertEqual(len(broker_allowed_tools(list(ALL_TOOLS))), len(READ_ONLY_TOOLS))
        with self.assertRaises(ValueError):
            broker_allowed_tools(["run_playbook"])

    def test_humans_and_agents_keep_full_allow_lists(self):
        m = self._mint(allowed_tools=["get_case", "run_playbook"])
        self.assertEqual(m.allowed_tools, ["get_case", "run_playbook"])
        m = self._mint(principal_type="agent", agent_id="a1", allowed_tools=["add_case_note"])
        self.assertEqual(m.allowed_tools, ["add_case_note"])
        self.assertIsNone(self._mint().allowed_tools)

    def test_type_is_case_insensitive(self):
        m = self._mint(principal_type=" Agent ", agent_id="a1")
        self.assertEqual(m.principal_type, "agent")

    def test_unknown_type_rejected(self):
        with self.assertRaises(ValueError):
            self._mint(principal_type="robot")
        self.assertEqual(self.store.list(), [])

    def test_agent_without_agent_id_rejected(self):
        for aid in (None, "", "   "):
            with self.subTest(agent_id=aid):
                with self.assertRaises(ValueError):
                    self._mint(principal_type="agent", agent_id=aid)
        self.assertEqual(self.store.list(), [])

    def test_legacy_entry_without_field_reads_as_mensch(self):
        m = self._mint()
        # Simulate a store written before the field existed.
        data = json.loads(self.store_path.read_text())
        for e in data["tokens"]:
            e.pop("principal_type", None)
            e.pop("agent_id", None)
        self.store_path.write_text(json.dumps(data))
        TokenStore._instances.clear()
        fresh = TokenStore.for_path(self.store_path)
        v = fresh.verify(m.raw_token)
        self.assertTrue(v.valid)
        self.assertEqual(v.principal_type, PRINCIPAL_HUMAN)
        self.assertIsNone(v.agent_id)
        self.assertEqual(fresh.list()[0].principal_type, PRINCIPAL_HUMAN)

    def test_store_version_unchanged(self):
        self._mint(principal_type="agent", agent_id="a1")
        data = json.loads(self.store_path.read_text())
        self.assertEqual(data["version"], 1)
        self.assertEqual(data["tokens"][0]["principal_type"], "agent")
        self.assertEqual(data["tokens"][0]["agent_id"], "a1")

    def test_normalise_principal_helper(self):
        self.assertEqual(normalise_principal(None), ("mensch", None))
        self.assertEqual(normalise_principal("", "x"), ("mensch", None))
        self.assertEqual(normalise_principal("agent", " a1 "), ("agent", "a1"))
        with self.assertRaises(ValueError):
            normalise_principal("agent")
        with self.assertRaises(ValueError):
            normalise_principal("nope")


class SanitiseArgsTest(unittest.TestCase):
    def test_redacts_sensitive_keys(self):
        out = sanitise_args_for_audit(
            {"name": "alice", "password": "hunter2", "api_key": "abc"})
        self.assertEqual(out["name"], "alice")
        self.assertEqual(out["password"], "<redacted>")
        self.assertEqual(out["api_key"], "<redacted>")

    def test_truncates_long_strings(self):
        long_val = "x" * 1000
        out = sanitise_args_for_audit({"description": long_val})
        # redact_nested (#28) truncates at _MAX_STR_LEN=500 with an original_len annotation
        self.assertIn("truncated", out["description"])
        self.assertLessEqual(len(out["description"]), 600)  # 500 chars + annotation overhead


class TestWriteToolGates(unittest.TestCase):
    """Prove write tools are correctly gated by config flags and enable_test_harness."""

    def _make_config(self, **kwargs) -> McpServerConfig:
        cfg = McpServerConfig()
        cfg.enabled_tools = set(READ_ONLY_TOOLS)
        for k, v in kwargs.items():
            setattr(cfg, k, v)
        return cfg

    def test_import_playbook_disabled_when_flag_false(self):
        """import_playbook must not appear in tools/list when tool flag is off."""
        cfg = self._make_config()
        self.assertNotIn("import_playbook", cfg.enabled_tools)

    def test_import_playbook_enabled_when_flag_true(self):
        """import_playbook appears in enabled_tools when explicitly added."""
        cfg = self._make_config()
        cfg.enabled_tools = set(READ_ONLY_TOOLS) | {"import_playbook"}
        self.assertIn("import_playbook", cfg.enabled_tools)

    def test_create_container_disabled_when_flag_false(self):
        """create_container not in read-only default set."""
        cfg = self._make_config()
        self.assertNotIn("create_container", cfg.enabled_tools)

    def test_create_container_requires_enable_test_harness(self):
        """create_container tool flag alone is not enough — enable_test_harness must also be true."""
        from soar_mcp_tools import tool_create_container

        class _FakeClient:
            pass

        cfg = self._make_config(enable_test_harness=False)
        cfg.enabled_tools = set(READ_ONLY_TOOLS) | {"create_container"}
        result = tool_create_container(_FakeClient(), cfg, {"name": "test", "label": "test", "severity": "low"})
        self.assertIn("enable_test_harness", result)
        self.assertIn("Error", result)

    def test_create_container_passes_gate_when_harness_enabled(self):
        """With enable_test_harness=True, create_container proceeds past the gate (may fail for other reasons)."""
        from soar_mcp_tools import tool_create_container

        class _FakeClient:
            def post(self, path, body):
                return {"id": 999, "success": True}, None

        cfg = self._make_config(enable_test_harness=True)
        result = tool_create_container(_FakeClient(), cfg, {"name": "test", "label": "test", "severity": "low"})
        self.assertNotIn("enable_test_harness", result)

    def test_run_playbook_not_in_read_only_tools(self):
        """run_playbook must not be in READ_ONLY_TOOLS."""
        self.assertNotIn("run_playbook", READ_ONLY_TOOLS)

    def test_create_artifact_not_in_read_only_tools(self):
        """create_artifact must not be in READ_ONLY_TOOLS."""
        self.assertNotIn("create_artifact", READ_ONLY_TOOLS)

    def test_all_new_playbook_builder_tools_in_all_tools(self):
        """All 6 v1.6.0+ tools must be registered in ALL_TOOLS."""
        for tool in ("list_apps", "list_assets", "get_action_schema", "export_playbook",
                     "import_playbook", "create_container"):
            with self.subTest(tool=tool):
                self.assertIn(tool, ALL_TOOLS)

    def test_read_tools_in_read_only_tools(self):
        """list_apps, list_assets, get_action_schema, export_playbook must be in READ_ONLY_TOOLS."""
        for tool in ("list_apps", "list_assets", "get_action_schema", "export_playbook"):
            with self.subTest(tool=tool):
                self.assertIn(tool, READ_ONLY_TOOLS)


if __name__ == "__main__":
    unittest.main()
