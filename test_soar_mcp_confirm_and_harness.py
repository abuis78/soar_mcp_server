"""Tests for #116 (persistent confirmation store) and #117 (harness portability)."""
from __future__ import annotations

import os
import tempfile
import unittest

from soar_mcp_config import McpServerConfig, READ_ONLY_TOOLS
from soar_mcp_tools import _ConfirmStore, call_tool


class ConfirmStorePersistenceTest(unittest.TestCase):
    """#116: a token issued by one 'process' must be consumable by another."""

    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.unlink(self.path)  # start absent

    def tearDown(self):
        for p in (self.path, self.path + ".tmp"):
            try:
                os.unlink(p)
            except OSError:
                pass

    def test_token_survives_across_store_instances(self):
        # Two separate _ConfirmStore instances on the same file simulate two
        # SOAR handler worker processes.
        issuer = _ConfirmStore(self.path)
        consumer = _ConfirmStore(self.path)
        args = {"name": "x", "label": "events"}
        token = issuer.issue("create_container", args)
        self.assertTrue(consumer.consume(token, "create_container", args))

    def test_single_use(self):
        s1, s2 = _ConfirmStore(self.path), _ConfirmStore(self.path)
        args = {"a": 1}
        tok = s1.issue("run_playbook", args)
        self.assertTrue(s2.consume(tok, "run_playbook", args))
        self.assertFalse(_ConfirmStore(self.path).consume(tok, "run_playbook", args))

    def test_changed_args_fail(self):
        s = _ConfirmStore(self.path)
        tok = s.issue("run_playbook", {"case_id": 1})
        self.assertFalse(_ConfirmStore(self.path).consume(tok, "run_playbook", {"case_id": 2}))

    def test_expired_fail(self):
        s = _ConfirmStore(self.path)
        tok = s.issue("run_playbook", {"a": 1}, ttl=0.0)
        self.assertFalse(_ConfirmStore(self.path).consume(tok, "run_playbook", {"a": 1}))

    def test_raw_token_not_stored(self):
        s = _ConfirmStore(self.path)
        tok = s.issue("run_playbook", {"a": 1})
        with open(self.path, encoding="utf-8") as fh:
            content = fh.read()
        self.assertNotIn(tok, content)  # only the hash is persisted


class _FakeContainerClient:
    def __init__(self, label="events", name="mcp_write_suite_1", delete_err=None,
                 get_err=None):
        self._label = label
        self._name = name
        self._delete_err = delete_err
        self._get_err = get_err
        self.deleted = False

    def get(self, path, params=None):
        if self._get_err:
            return None, self._get_err
        return {"id": 3, "label": self._label, "name": self._name}, None

    def delete(self, path):
        if self._delete_err:
            return None, self._delete_err
        self.deleted = True
        return {"success": True}, None


def _harness_cfg(**over):
    c = McpServerConfig()
    c.enable_test_harness = True
    c.advisory_disclaimer = False
    c.enabled_tools = set(READ_ONLY_TOOLS) | {"delete_container"}
    for k, v in over.items():
        setattr(c, k, v)
    return c


class DeleteContainerPortabilityTest(unittest.TestCase):
    """#117: suite-owned detection by configured label OR name prefix."""

    def test_delete_by_name_prefix_even_if_label_differs(self):
        client = _FakeContainerClient(label="events", name="mcp_write_suite_1")
        out = call_tool("delete_container", {"container_id": 3}, client, _harness_cfg())
        self.assertTrue(client.deleted, out)
        self.assertIn("deleted", out)

    def test_delete_by_configured_label(self):
        client = _FakeContainerClient(label="events", name="something_else")
        out = call_tool("delete_container", {"container_id": 3}, client,
                        _harness_cfg(test_container_label="events"))
        self.assertTrue(client.deleted, out)

    def test_refuses_non_suite_container(self):
        client = _FakeContainerClient(label="production", name="real_case")
        out = call_tool("delete_container", {"container_id": 3}, client, _harness_cfg())
        self.assertFalse(client.deleted)
        self.assertIn("Refusing to delete", out)

    def test_403_is_actionable_cleanup_finding(self):
        client = _FakeContainerClient(
            name="mcp_x", delete_err="Access denied (HTTP 403). Not authorized.")
        out = call_tool("delete_container", {"container_id": 3}, client, _harness_cfg())
        self.assertIn("Cleanup incomplete", out)
        self.assertIn("delete permission", out)

    def test_get_failure_refuses_delete_without_confirm(self):
        # #126: if the container GET fails, do NOT delete (fail-safe).
        client = _FakeContainerClient(get_err="Resource not found (HTTP 404).")
        out = call_tool("delete_container", {"container_id": 3}, client, _harness_cfg())
        self.assertFalse(client.deleted, out)
        self.assertIn("could not read it", out)

    def test_get_failure_allows_delete_with_confirm(self):
        client = _FakeContainerClient(get_err="Connection error.")
        out = call_tool("delete_container", {"container_id": 3, "confirm": True},
                        client, _harness_cfg())
        self.assertTrue(client.deleted, out)


if __name__ == "__main__":
    unittest.main()
