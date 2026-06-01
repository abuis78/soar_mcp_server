"""Unit tests for soar_mcp_tokens.TokenStore.

Run from inside the phantom_soar_mcp_server/ directory:
    python3 -m unittest test_soar_mcp_tokens -v
"""
from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path

from soar_mcp_tokens import TokenStore, sanitise_args_for_audit


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
        self.assertTrue(out["description"].endswith("<truncated>"))
        self.assertLessEqual(len(out["description"]), 220)


if __name__ == "__main__":
    unittest.main()
