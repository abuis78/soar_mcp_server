"""Custom Function read-only discovery tools — slice S1 (issue #155)."""
from __future__ import annotations

import json
import unittest

from soar_mcp_config import ALL_TOOLS, READ_ONLY_TOOLS, McpServerConfig
from soar_mcp_tools import (
    TOOL_SCHEMAS,
    _TOOL_HANDLERS,
    tool_detect_custom_function_capabilities,
    tool_get_custom_function,
    tool_list_custom_functions,
)

_CF_TOOLS = ("list_custom_functions", "get_custom_function",
             "detect_custom_function_capabilities")


def _cf(cf_id=1, name="normalize_domain", draft=False, source=None):
    d = {
        "id": cf_id, "name": name, "scm_id": 1, "description": "desc",
        "draft_mode": draft, "disabled": False, "passed_validation": True,
        "commit_sha": "7e08d23", "inputs": [{"name": "domain"}],
        "outputs": [{"data_path": "normalized"}],
        "playbooks": [{"id": 5, "name": "pb", "active": True}],
        "warnings": [], "errors": [],
    }
    if source is not None:
        d["python"] = source
    return d


class _FakeClient:
    def __init__(self, items=None, detail=None, list_err=None, detail_err=None,
                 scm=None, scm_err=None):
        self._base_url = "https://s/rest"
        self._items = items if items is not None else [_cf()]
        self._detail = detail
        self._list_err = list_err
        self._detail_err = detail_err
        self._scm = scm if scm is not None else [{"id": 1, "name": "local"}]
        self._scm_err = scm_err
        self.last_params = None

    def get(self, path, params=None):
        if path == "custom_function":
            self.last_params = params
            if self._list_err:
                return None, self._list_err
            return {"data": self._items, "count": len(self._items)}, None
        if path.startswith("custom_function/"):
            if self._detail_err:
                return None, self._detail_err
            return (self._detail if self._detail is not None else _cf()), None
        if path == "scm":
            if self._scm_err:
                return None, self._scm_err
            return {"data": self._scm}, None
        return {}, None


def _cfg():
    return McpServerConfig()


def _json(out):
    return json.loads(out)


class RegistrationTest(unittest.TestCase):
    def test_tools_are_registered_and_read_only(self):
        for t in _CF_TOOLS:
            self.assertIn(t, ALL_TOOLS, t)
            self.assertIn(t, READ_ONLY_TOOLS, t)        # no write surface in S1
            self.assertIn(t, TOOL_SCHEMAS, t)
            self.assertIn(t, _TOOL_HANDLERS, t)


class ListCustomFunctionsTest(unittest.TestCase):
    def test_lists_and_never_exposes_source(self):
        c = _FakeClient(items=[_cf(source="def f(): pass")])
        env = _json(tool_list_custom_functions(c, _cfg(), {"output_format": "json"}))
        self.assertTrue(env["ok"])
        fn = env["data"]["custom_functions"][0]
        self.assertEqual(fn["id"], 1)
        self.assertEqual(fn["revision"], "7e08d23")   # commit_sha -> S2 concurrency token
        self.assertNotIn("source", fn)
        self.assertNotIn("python", fn)

    def test_name_uses_server_side_filter(self):
        c = _FakeClient()
        tool_list_custom_functions(c, _cfg(), {"name": "normalize", "output_format": "json"})
        self.assertIn("_filter_name__icontains", c.last_params)
        self.assertIn("normalize", c.last_params["_filter_name__icontains"])

    def test_include_drafts_false_filters(self):
        c = _FakeClient(items=[_cf(1, "a", draft=False), _cf(2, "b", draft=True)])
        env = _json(tool_list_custom_functions(
            c, _cfg(), {"include_drafts": False, "output_format": "json"}))
        names = [f["name"] for f in env["data"]["custom_functions"]]
        self.assertEqual(names, ["a"])

    def test_error_is_envelope_not_exception(self):
        c = _FakeClient(list_err="403 forbidden")
        env = _json(tool_list_custom_functions(c, _cfg(), {"output_format": "json"}))
        self.assertFalse(env["ok"])
        self.assertEqual(env["errors"][0]["code"], "CF_LIST_FAILED")


class GetCustomFunctionTest(unittest.TestCase):
    def test_source_omitted_by_default(self):
        c = _FakeClient(detail=_cf(source="def f(): pass"))
        env = _json(tool_get_custom_function(
            c, _cfg(), {"custom_function_id": 1, "output_format": "json"}))
        self.assertTrue(env["ok"])
        self.assertNotIn("source", env["data"])          # opt-in only
        self.assertIn("playbooks", env["data"])          # associations are free
        self.assertIn("warnings", env["data"])           # native validation rides along

    def test_source_included_on_request_with_hash(self):
        src = "def f(): return 1"
        c = _FakeClient(detail=_cf(source=src))
        env = _json(tool_get_custom_function(
            c, _cfg(), {"custom_function_id": 1, "include_source": True,
                        "output_format": "json"}))
        self.assertEqual(env["data"]["source"], src)
        self.assertEqual(len(env["data"]["source_sha256"]), 64)
        self.assertFalse(env["data"]["source_truncated"])

    def test_secret_pattern_raises_finding(self):
        c = _FakeClient(detail=_cf(source='api_key = "abc123"'))
        env = _json(tool_get_custom_function(
            c, _cfg(), {"custom_function_id": 1, "include_source": True,
                        "output_format": "json"}))
        codes = [f["code"] for f in env["findings"]]
        self.assertIn("SOURCE_MAY_CONTAIN_SECRETS", codes)

    def test_failed_validation_raises_finding(self):
        d = _cf()
        d["passed_validation"] = False
        c = _FakeClient(detail=d)
        env = _json(tool_get_custom_function(
            c, _cfg(), {"custom_function_id": 1, "output_format": "json"}))
        self.assertIn("NOT_PASSED_VALIDATION", [f["code"] for f in env["findings"]])

    def test_bad_id_is_envelope_error(self):
        c = _FakeClient()
        env = _json(tool_get_custom_function(
            c, _cfg(), {"custom_function_id": 0, "output_format": "json"}))
        self.assertFalse(env["ok"])


class CapabilityProbeTest(unittest.TestCase):
    def test_probe_reports_observed_and_unknowns(self):
        c = _FakeClient()
        env = _json(tool_detect_custom_function_capabilities(
            c, _cfg(), {"output_format": "json"}))
        caps = env["data"]["capabilities"]
        self.assertTrue(env["ok"])
        self.assertEqual(caps["list"], "supported")
        self.assertEqual(caps["read"], "supported")
        self.assertEqual(caps["revision_token"], "supported")
        self.assertEqual(caps["associations"], "supported")
        # never assumed from documentation alone
        for op in ("create_draft", "update_draft", "delete_draft", "publish",
                   "runtime_test", "direct_result_read", "export"):
            self.assertEqual(caps[op], "unknown", op)
        self.assertEqual(env["data"]["repositories"], [{"id": 1, "name": "local"}])

    def test_probe_never_write_probes(self):
        calls = []

        class _Spy(_FakeClient):
            def get(self, path, params=None):
                calls.append(("GET", path))
                return super().get(path, params)

            def post(self, path, body):      # must never be called
                calls.append(("POST", path))
                raise AssertionError("capability probe must not write")

        tool_detect_custom_function_capabilities(_Spy(), _cfg(), {"output_format": "json"})
        self.assertTrue(calls)
        self.assertTrue(all(m == "GET" for m, _ in calls), calls)

    def test_list_failure_is_reported_not_raised(self):
        c = _FakeClient(list_err="401 unauthorized")
        env = _json(tool_detect_custom_function_capabilities(
            c, _cfg(), {"output_format": "json"}))
        self.assertFalse(env["ok"])
        self.assertEqual(env["data"]["capabilities"]["list"], "unsupported")
        self.assertIn("CF_LIST_FAILED", [f["code"] for f in env["findings"]])


if __name__ == "__main__":
    unittest.main()
