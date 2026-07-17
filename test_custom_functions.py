"""Custom Function read-only discovery tools — slice S1 (issue #155)."""
from __future__ import annotations

import json
import unittest

from soar_mcp_config import ALL_TOOLS, READ_ONLY_TOOLS, McpServerConfig
from soar_mcp_tools import (
    tool_create_custom_function_draft,
    tool_update_custom_function_draft,
    TOOL_SCHEMAS,
    _TOOL_HANDLERS,
    tool_detect_custom_function_capabilities,
    tool_get_custom_function,
    tool_list_custom_functions,
)

_CF_TOOLS = ("list_custom_functions", "get_custom_function",
             "detect_custom_function_capabilities")


def _cf(cf_id=1, name="normalize_domain", draft=False, source=None):
    """A DETAIL record (GET /rest/custom_function/<id>)."""
    d = {
        "id": cf_id, "name": name, "scm_id": 2, "description": "desc",
        "draft_mode": draft, "disabled": False, "passed_validation": True,
        "commit_sha": "7e08d23", "inputs": [{"name": "domain", "input_type": "item"}],
        "outputs": [{"data_path": "normalized"}],
        "playbooks": [{"id": 5, "name": "pb", "active": True}],
        "is_read_only": False, "python_version": "3.13", "version": 1,
    }
    if source is not None:
        d["python"] = source
    return d


def _cf_list_row(cf_id=1, name="normalize_domain", draft=False):
    """A LIST row as SOAR 8.5.0.248 really returns it: scm_id null, no inputs/outputs."""
    return {
        "id": cf_id, "name": name, "scm_id": None, "description": "desc",
        "draft_mode": draft, "disabled": False, "passed_validation": False,
        "commit_sha": "7e08d23",
    }


class _FakeClient:
    def __init__(self, items=None, detail=None, list_err=None, detail_err=None,
                 scm=None, scm_err=None):
        self._base_url = "https://s/rest"
        self._items = items if items is not None else [_cf()]
        self._detail = detail
        self._list_err = list_err
        self._detail_err = detail_err
        # Real mapping on the reference instance: community=1, local=2 (#157) —
        # do not encode the 'local == 1' assumption the source spec got wrong.
        self._scm = scm if scm is not None else [{"id": 1, "name": "community"},
                                                 {"id": 2, "name": "local"}]
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

    def test_sparse_list_row_omits_counts_instead_of_faking_zero(self):
        # #157: SOAR's list projection has no inputs/outputs/scm_id. Reporting 0/null
        # would tell the agent "no inputs" when the truth is "not returned".
        c = _FakeClient(items=[_cf_list_row()])
        env = _json(tool_list_custom_functions(c, _cfg(), {"output_format": "json"}))
        fn = env["data"]["custom_functions"][0]
        for absent in ("input_count", "output_count", "playbook_count", "scm_id"):
            self.assertNotIn(absent, fn, absent)
        self.assertIn("LIST_PROJECTION_SPARSE", [f["code"] for f in env["findings"]])

    def test_full_row_does_report_counts(self):
        c = _FakeClient(items=[_cf()])
        env = _json(tool_list_custom_functions(c, _cfg(), {"output_format": "json"}))
        fn = env["data"]["custom_functions"][0]
        self.assertEqual(fn["input_count"], 1)
        self.assertEqual(fn["scm_id"], 2)
        self.assertNotIn("LIST_PROJECTION_SPARSE", [f["code"] for f in env["findings"]])

    def test_cap_truncation_is_disclosed(self):
        class _Capped(_FakeClient):
            def get(self, path, params=None):
                if path == "custom_function":
                    return {"data": [_cf_list_row(1, "a")], "count": 157}, None
                return super().get(path, params)
        env = _json(tool_list_custom_functions(_Capped(), _cfg(), {"output_format": "json"}))
        codes = [f["code"] for f in env["findings"]]
        self.assertIn("CAP_TRUNCATED", codes)

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
        # NOTE: warnings/errors are NOT asserted here — 8.5.0.248 does not return them
        # on GET, and faking them as [] is exactly the defect #157 fixed.

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

    def test_failed_validation_warns_only_with_evidence(self):
        # #157: with warnings present the warn is actionable...
        d = _cf()
        d["passed_validation"] = False
        d["warnings"] = ["line 3: unused import"]
        c = _FakeClient(detail=d)
        env = _json(tool_get_custom_function(
            c, _cfg(), {"custom_function_id": 1, "output_format": "json"}))
        self.assertIn("NOT_PASSED_VALIDATION", [f["code"] for f in env["findings"]])

    def test_failed_validation_alone_is_not_noise(self):
        # ...but on 8.5.0.248 passed_validation is false for EVERY function and no
        # warnings/errors are returned -> warning on the flag alone would be noise.
        d = _cf()
        d["passed_validation"] = False
        c = _FakeClient(detail=d)
        env = _json(tool_get_custom_function(
            c, _cfg(), {"custom_function_id": 1, "output_format": "json"}))
        codes = [f["code"] for f in env["findings"]]
        self.assertNotIn("NOT_PASSED_VALIDATION", codes)
        self.assertIn("VALIDATION_DETAIL_UNAVAILABLE", codes)

    def test_warnings_absent_are_not_faked_as_empty(self):
        c = _FakeClient(detail=_cf())          # build returns no warnings/errors on GET
        env = _json(tool_get_custom_function(
            c, _cfg(), {"custom_function_id": 1, "output_format": "json"}))
        self.assertNotIn("warnings", env["data"])   # never claim "no warnings"
        self.assertNotIn("errors", env["data"])

    def test_safety_fields_passed_through(self):
        c = _FakeClient(detail=_cf())
        env = _json(tool_get_custom_function(
            c, _cfg(), {"custom_function_id": 1, "output_format": "json"}))
        self.assertIs(env["data"]["is_read_only"], False)   # S2 write gate
        self.assertEqual(env["data"]["python_version"], "3.13")

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
        self.assertEqual(env["data"]["repositories"],
                         [{"id": 1, "name": "community"}, {"id": 2, "name": "local"}])

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


class _WriteClient(_FakeClient):
    """Records writes so tests can prove a blocked path never wrote."""
    def __init__(self, detail=None, **kw):
        super().__init__(detail=detail, **kw)
        self.posts = []

    def post(self, path, body):
        self.posts.append((path, body))
        return {"id": 99, "name": "new_fn", "draft_mode": True, "commit_sha": "abc"}, None


def _wcfg(allow=(2,)):
    c = McpServerConfig()
    c.custom_function_write_scm_ids = list(allow)
    return c


class DraftWriteRegistrationTest(unittest.TestCase):
    def test_write_tools_are_write_not_read_only(self):
        from soar_mcp_tools import _WRITE_TOOLS
        for t in ("create_custom_function_draft", "update_custom_function_draft"):
            self.assertIn(t, ALL_TOOLS, t)
            self.assertNotIn(t, READ_ONLY_TOOLS, t)
            self.assertIn(t, _WRITE_TOOLS, t)      # -> #50 confirmation gate applies
            self.assertIn(t, TOOL_SCHEMAS, t)
            self.assertIn(t, _TOOL_HANDLERS, t)


class CreateDraftGateTest(unittest.TestCase):
    def _create(self, cfg, **over):
        args = {"name": "fn", "scm_id": 2, "source": "def fn(): pass",
                "commit_message": "msg", "dry_run": False, "output_format": "json"}
        args.update(over)
        c = _WriteClient()
        return c, _json(tool_create_custom_function_draft(c, cfg, args))

    def test_empty_allowlist_blocks_every_write(self):
        c, env = self._create(_wcfg(allow=()))
        self.assertFalse(env["ok"])
        self.assertEqual(env["errors"][0]["code"], "WRITE_REPO_NOT_ALLOWED")
        self.assertEqual(c.posts, [])           # nothing written

    def test_repo_outside_allowlist_blocks(self):
        c, env = self._create(_wcfg(allow=(2,)), scm_id=1)   # 1 = community
        self.assertFalse(env["ok"])
        self.assertEqual(env["errors"][0]["code"], "WRITE_REPO_NOT_ALLOWED")
        self.assertEqual(c.posts, [])

    def test_publish_attempt_blocked(self):
        c, env = self._create(_wcfg(), draft_mode=False)
        self.assertFalse(env["ok"])
        self.assertEqual(env["errors"][0]["code"], "PUBLISH_NOT_SUPPORTED")
        self.assertEqual(c.posts, [])

    def test_source_without_commit_message_blocked(self):
        c, env = self._create(_wcfg(), commit_message="")
        self.assertFalse(env["ok"])
        self.assertEqual(env["errors"][0]["code"], "BAD_INPUT")
        self.assertEqual(c.posts, [])

    def test_dry_run_is_default_and_writes_nothing(self):
        c = _WriteClient()
        env = _json(tool_create_custom_function_draft(
            c, _wcfg(), {"name": "fn", "scm_id": 2, "source": "def fn(): pass",
                         "commit_message": "m", "output_format": "json"}))
        self.assertTrue(env["ok"])
        self.assertTrue(env["data"]["dry_run"])
        self.assertEqual(c.posts, [])
        # preview never echoes the full source back
        self.assertIn("sha256=", env["data"]["payload_preview"]["python"])

    def test_real_create_forces_draft_mode(self):
        c, env = self._create(_wcfg())
        self.assertTrue(env["ok"])
        path, body = c.posts[0]
        self.assertEqual(path, "custom_function")
        self.assertIs(body["draft_mode"], True)          # always a draft
        self.assertEqual(body["scm_id"], 2)
        self.assertEqual(body["commit_message"], "msg")


class UpdateDraftGateTest(unittest.TestCase):
    def _update(self, cfg, detail=None, **over):
        args = {"custom_function_id": 1, "expected_revision": "7e08d23",
                "source": "def fn(): pass", "commit_message": "m",
                "dry_run": False, "output_format": "json"}
        args.update(over)
        d = detail if detail is not None else _cf(draft=True)
        c = _WriteClient(detail=d)
        return c, _json(tool_update_custom_function_draft(c, cfg, args))

    def test_revision_conflict_blocks_without_force(self):
        c, env = self._update(_wcfg(), expected_revision="stale")
        self.assertFalse(env["ok"])
        self.assertEqual(env["errors"][0]["code"], "REVISION_CONFLICT")
        self.assertEqual(c.posts, [])

    def test_read_only_function_blocks(self):
        d = _cf(draft=True)
        d["is_read_only"] = True
        c, env = self._update(_wcfg(), detail=d)
        self.assertFalse(env["ok"])
        self.assertEqual(env["errors"][0]["code"], "CF_READ_ONLY")
        self.assertEqual(c.posts, [])

    def test_repo_outside_allowlist_blocks(self):
        d = _cf(draft=True)
        d["scm_id"] = 1                      # community
        c, env = self._update(_wcfg(allow=(2,)), detail=d)
        self.assertFalse(env["ok"])
        self.assertEqual(env["errors"][0]["code"], "WRITE_REPO_NOT_ALLOWED")
        self.assertEqual(c.posts, [])

    def test_missing_expected_revision_blocks(self):
        c, env = self._update(_wcfg(), expected_revision="")
        self.assertFalse(env["ok"])
        self.assertEqual(env["errors"][0]["code"], "BAD_INPUT")
        self.assertEqual(c.posts, [])

    def test_update_never_sends_immutable_identity(self):
        c, env = self._update(_wcfg())
        self.assertTrue(env["ok"])
        path, body = c.posts[0]
        self.assertEqual(path, "custom_function/1")
        self.assertNotIn("name", body)       # immutable per API
        self.assertNotIn("scm_id", body)
        self.assertIs(body["draft_mode"], True)

    def test_non_draft_target_warns(self):
        c, env = self._update(_wcfg(), detail=_cf(draft=False))
        self.assertTrue(env["ok"])
        self.assertIn("TARGET_WAS_NOT_A_DRAFT", [f["code"] for f in env["findings"]])


class ScmIdAllowlistParseTest(unittest.TestCase):
    def test_parse_is_fail_safe(self):
        from soar_mcp_config import McpConfigLoader
        p = McpConfigLoader._parse_scm_ids
        self.assertEqual(p("2"), [2])
        self.assertEqual(p(" 2 , 4 ,2"), [2, 4])        # trimmed + deduped
        self.assertEqual(p(""), [])                      # empty -> no writes
        self.assertEqual(p(None), [])
        self.assertEqual(p("2,abc,-1,0"), [2])           # junk never widens the allowlist


if __name__ == "__main__":
    unittest.main()
