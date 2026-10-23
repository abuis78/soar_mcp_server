"""Contract tests for policy/client.py (SPEC-MCP Phase 2.2, wire aligned to
policy_client.base in Phase 3.1, MCP-09).

A local plain-HTTP server plays the Policy Manager. TLS is not exercised
here (no certificates in the repo, L8); the mTLS path is covered up to the
SSL-context construction with unusable dummy files.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from policy.client import (
    CODE_CONSUMED,
    CODE_DUPLICATE,
    CODE_EXPIRED,
    CODE_HALTED,
    CODE_INVALID_RESPONSE,
    CODE_NOT_APPROVED,
    CODE_SELF_APPROVAL,
    CODE_UNKNOWN_APPROVAL,
    ApprovalStatus,
    ConsumeResult,
    HaltStatus,
    HttpPolicyClient,
    PolicyClientError,
    PolicyDecision,
    StubPolicyClient,
    approval_ref,
    build_policy_client,
    redact_path,
)
from soar_mcp_config import McpServerConfig

# PM spec §5 example response, verbatim field set.
EXAMPLE_DECISION = {
    "entscheidung_id": "pm-2026-10-17-000088",
    "gate": "APPROVE_2PERSON",
    "freigaben_noetig": 2,
    "risiko_score": 0.42,
    "policy_version": "c7d0b19",
    "begruendung": [
        {"regel": "kategorie", "gate": "APPROVE_2PERSON"},
        {"regel": "risiko", "wert": 0.42, "gate": "APPROVE_1CLICK"},
    ],
    "freigabe_id": "ap-5521",
    "ablauf": "2026-10-17T09:20:00+02:00",
}


class _FakePolicyManager:
    """Scriptable responses: route -> (status, body or bytes, delay_s)."""

    def __init__(self):
        self.routes: dict[tuple[str, str], tuple[int, object, float]] = {}
        self.requests: list[tuple[str, str, object]] = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a):  # silence
                pass

            def _serve(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                try:
                    parsed = json.loads(body) if body else None
                except ValueError:
                    parsed = body
                server.requests.append((self.command, self.path, parsed))
                status, payload, delay = server.routes.get(
                    (self.command, self.path), (404, {"error": "no route"}, 0.0))
                if delay:
                    time.sleep(delay)
                raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            do_GET = _serve
            do_POST = _serve

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def route(self, method: str, path: str, status: int, payload: object, delay: float = 0.0):
        self.routes[(method, path)] = (status, payload, delay)

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class HttpPolicyClientTest(unittest.TestCase):
    def setUp(self):
        self.pm = _FakePolicyManager()
        self.addCleanup(self.pm.close)
        self.client = HttpPolicyClient(self.pm.url, 1.0, allow_insecure_http=True)

    # -- decide -------------------------------------------------------------

    def test_decide_parses_spec_example_and_posts_request(self):
        self.pm.route("POST", "/v1/decide", 200, EXAMPLE_DECISION)
        request = {"aktion": {"art": "run_playbook"}, "kontext": {"stufe": 3}}
        d = self.client.decide(request)
        self.assertEqual(d.entscheidung_id, "pm-2026-10-17-000088")
        self.assertEqual(d.gate, "APPROVE_2PERSON")
        self.assertEqual(d.freigaben_noetig, 2)
        self.assertEqual(d.freigabe_id, "ap-5521")
        self.assertAlmostEqual(d.risiko_score, 0.42)
        self.assertEqual(d.policy_version, "c7d0b19")
        self.assertEqual(len(d.begruendung), 2)
        self.assertEqual(d.ablauf, "2026-10-17T09:20:00+02:00")
        self.assertTrue(d.needs_approval)
        self.assertIsNone(d.code)
        method, path, body = self.pm.requests[0]
        self.assertEqual((method, path), ("POST", "/v1/decide"))
        self.assertEqual(body, request)

    def test_decide_allow_without_freigabe_id_is_fine(self):
        self.pm.route("POST", "/v1/decide", 200, {"entscheidung_id": "pm-1", "gate": "allow"})
        d = self.client.decide({})
        self.assertEqual(d.gate, "ALLOW")
        self.assertFalse(d.needs_approval)

    def test_decide_deny_carries_code(self):
        self.pm.route("POST", "/v1/decide", 200,
                      {"entscheidung_id": "pm-2", "gate": "DENY", "code": "HALTED"})
        d = self.client.decide({})
        self.assertEqual((d.gate, d.code), ("DENY", "HALTED"))

    def test_decide_approval_gate_without_freigabe_id_is_contract_error(self):
        self.pm.route("POST", "/v1/decide", 200, {"entscheidung_id": "pm-3", "gate": "APPROVE_1CLICK"})
        with self.assertRaises(PolicyClientError) as cm:
            self.client.decide({})
        self.assertEqual(cm.exception.kind, "contract")

    def test_decide_unknown_gate_is_contract_error(self):
        self.pm.route("POST", "/v1/decide", 200, {"entscheidung_id": "pm-4", "gate": "MAYBE"})
        with self.assertRaises(PolicyClientError) as cm:
            self.client.decide({})
        self.assertEqual(cm.exception.kind, "contract")

    def test_decide_missing_id_is_contract_error(self):
        for gate in ("ALLOW", "APPROVE_1CLICK"):
            self.pm.route("POST", "/v1/decide", 200, {"gate": gate, "freigabe_id": "ap-1"})
            with self.assertRaises(PolicyClientError) as cm:
                self.client.decide({})
            self.assertEqual(cm.exception.kind, "contract", gate)

    def test_decide_deny_may_come_without_id(self):
        """policy_client.base: client-side denies carry an empty entscheidung_id."""
        self.pm.route("POST", "/v1/decide", 200, {"entscheidung_id": "", "gate": "DENY", "code": "NO_INITIATOR"})
        d = self.client.decide({})
        self.assertEqual((d.gate, d.entscheidung_id, d.code), ("DENY", "", "NO_INITIATOR"))

    def test_decide_http_500_is_http_error(self):
        self.pm.route("POST", "/v1/decide", 500, {"error": "boom"})
        with self.assertRaises(PolicyClientError) as cm:
            self.client.decide({})
        self.assertEqual(cm.exception.kind, "http")

    def test_decide_invalid_json_is_contract_error(self):
        self.pm.route("POST", "/v1/decide", 200, b"{not json")
        with self.assertRaises(PolicyClientError) as cm:
            self.client.decide({})
        self.assertEqual(cm.exception.kind, "contract")

    def test_decide_non_object_body_is_contract_error(self):
        self.pm.route("POST", "/v1/decide", 200, ["ALLOW"])
        with self.assertRaises(PolicyClientError) as cm:
            self.client.decide({})
        self.assertEqual(cm.exception.kind, "contract")

    def test_decide_timeout_is_timeout_error_no_retry(self):
        self.pm.route("POST", "/v1/decide", 200, EXAMPLE_DECISION, delay=0.8)
        client = HttpPolicyClient(self.pm.url, 0.2, allow_insecure_http=True)
        with self.assertRaises(PolicyClientError) as cm:
            client.decide({})
        self.assertEqual(cm.exception.kind, "timeout")
        time.sleep(0.9)  # let the delayed handler finish
        self.assertEqual(len(self.pm.requests), 1)

    def test_decide_unreachable_is_unreachable_error(self):
        dead = _FakePolicyManager()
        url = dead.url
        dead.close()
        client = HttpPolicyClient(url, 0.5, allow_insecure_http=True)
        with self.assertRaises(PolicyClientError) as cm:
            client.decide({})
        self.assertEqual(cm.exception.kind, "unreachable")

    def test_decide_rejects_non_dict_request(self):
        with self.assertRaises(PolicyClientError):
            self.client.decide(["x"])  # type: ignore[arg-type]
        self.assertEqual(self.pm.requests, [])

    # -- halt ---------------------------------------------------------------

    def test_halt_status_true_false(self):
        """HaltStatus wire: {"angehalten": bool, "grund": str}."""
        self.pm.route("GET", "/v1/halt", 200, {"angehalten": True, "grund": "incident"})
        st = self.client.halt_status()
        self.assertIsInstance(st, HaltStatus)
        self.assertEqual((st.halted, st.grund), (True, "incident"))
        self.pm.route("GET", "/v1/halt", 200, {"angehalten": False, "grund": ""})
        self.assertFalse(self.client.halt_status().halted)

    def test_halt_status_unknown_counts_as_halted(self):
        for status, body in ((500, {"error": "x"}), (200, {"state": "running"}),
                             (200, {"angehalten": "no"}), (200, {"halted": False})):
            self.pm.route("GET", "/v1/halt", status, body)
            self.assertTrue(self.client.halt_status().halted, body)

    # -- health -------------------------------------------------------------

    def test_health_ok_and_failure(self):
        self.pm.route("GET", "/health", 200, {"status": "ok"})
        self.assertEqual(self.client.health()["status"], "ok")
        self.pm.route("GET", "/health", 503, {"status": "down"})
        with self.assertRaises(PolicyClientError) as cm:
            self.client.health()
        self.assertEqual(cm.exception.kind, "http")

    # -- approvals ----------------------------------------------------------

    def test_approval_status_and_consume(self):
        """ApprovalStatus / ConsumeResult wire (policy_client.base)."""
        self.pm.route("GET", "/v1/approvals/ap-5521", 200,
                      {"freigabe_id": "ap-5521", "status": "approved", "erteilt": 2, "noetig": 2})
        self.pm.route("POST", "/v1/approvals/ap-5521/consume", 200, {"gueltig": True})
        st = self.client.approval_status("ap-5521")
        self.assertIsInstance(st, ApprovalStatus)
        self.assertEqual((st.status, st.erteilt, st.noetig, st.approved, st.code), ("approved", 2, 2, True, None))
        request = {"aktion": {"art": "run_playbook"}, "kontext": {}}
        res = self.client.consume("ap-5521", request)
        self.assertIsInstance(res, ConsumeResult)
        self.assertTrue(res.ok)
        self.assertEqual([r[:2] for r in self.pm.requests],
                         [("GET", "/v1/approvals/ap-5521"), ("POST", "/v1/approvals/ap-5521/consume")])
        self.assertEqual(self.pm.requests[1][2], request)  # consume carries the unchanged action

    def test_approve_and_reject_post_the_approver(self):
        self.pm.route("POST", "/v1/approvals/ap-1/approve", 200,
                      {"freigabe_id": "ap-1", "status": "pending", "erteilt": 1, "noetig": 2})
        self.pm.route("POST", "/v1/approvals/ap-1/reject", 200,
                      {"freigabe_id": "ap-1", "status": "rejected", "erteilt": 1, "noetig": 2})
        st = self.client.approve("ap-1", "bob")
        self.assertEqual((st.status, st.erteilt, st.noetig, st.pending), ("pending", 1, 2, True))
        self.assertEqual(self.pm.requests[-1], ("POST", "/v1/approvals/ap-1/approve", {"freigebender": "bob"}))
        st = self.client.reject("ap-1", "bob")
        self.assertEqual(st.status, "rejected")
        self.assertEqual(self.pm.requests[-1], ("POST", "/v1/approvals/ap-1/reject", {"freigebender": "bob"}))

    def test_approve_carries_lifecycle_code(self):
        self.pm.route("POST", "/v1/approvals/ap-1/approve", 200,
                      {"freigabe_id": "ap-1", "status": "pending", "erteilt": 0, "noetig": 2, "code": "SELF_APPROVAL"})
        st = self.client.approve("ap-1", "alice")
        self.assertEqual((st.status, st.code), ("pending", CODE_SELF_APPROVAL))

    def test_unknown_approval_status_counts_as_expired(self):
        self.pm.route("GET", "/v1/approvals/ap-1", 200, {"status": "weird"})
        st = self.client.approval_status("ap-1")
        self.assertEqual((st.freigabe_id, st.status), ("ap-1", "expired"))

    def test_consume_not_valid_is_not_ok(self):
        self.pm.route("POST", "/v1/approvals/ap-1/consume", 200, {"gueltig": False, "code": "EXPIRED"})
        res = self.client.consume("ap-1", {})
        self.assertEqual((res.ok, res.code), (False, CODE_EXPIRED))
        self.pm.route("POST", "/v1/approvals/ap-1/consume", 200, {"ok": True})
        res = self.client.consume("ap-1", {})
        self.assertEqual((res.ok, res.code), (False, CODE_INVALID_RESPONSE))
        self.pm.route("POST", "/v1/approvals/ap-1/consume", 200, {"gueltig": "true"})
        self.assertFalse(self.client.consume("ap-1", {}).ok)

    def test_consume_transport_failure_raises(self):
        self.pm.route("POST", "/v1/approvals/ap-1/consume", 409, {"error": "expired"})
        with self.assertRaises(PolicyClientError) as cm:
            self.client.consume("ap-1", {})
        self.assertEqual(cm.exception.kind, "http")

    def test_error_texts_never_carry_the_approval_id(self):
        """PM-F42 / S14: PolicyClientError.reason shows #<approval_ref>, never the id."""
        self.pm.route("POST", "/v1/approvals/ap-1/consume", 409, {"error": "expired"})
        self.pm.route("GET", "/v1/approvals/ap-1", 500, {})
        for call in (lambda: self.client.consume("ap-1", {}), lambda: self.client.approval_status("ap-1"),
                     lambda: self.client.approve("ap-1", "bob")):
            with self.assertRaises(PolicyClientError) as cm:
                call()
            self.assertNotIn("ap-1", cm.exception.reason)
            self.assertIn("/v1/approvals/#" + approval_ref("ap-1"), cm.exception.reason)

    def test_logs_carry_the_approval_ref_not_the_id(self):
        self.pm.route("POST", "/v1/decide", 200, EXAMPLE_DECISION)
        self.pm.route("POST", "/v1/approvals/ap-1/consume", 200, {"gueltig": True})
        with self.assertLogs("soar_mcp.policy_client", level="INFO") as cm:
            d = self.client.decide({})
            self.client.consume("ap-1", {})
        log = "\n".join(cm.output)
        self.assertIn("freigabe_ref=" + approval_ref(d.freigabe_id), log)
        self.assertIn("freigabe_ref=" + approval_ref("ap-1"), log)
        self.assertNotIn(d.freigabe_id, log)
        self.assertNotIn("ap-1", log)

    def test_malformed_freigabe_id_or_approver_never_hits_the_wire(self):
        for bad in ("../admin/halt", "ap 1", "", "a" * 200, None):
            with self.assertRaises(PolicyClientError):
                self.client.consume(bad, {})  # type: ignore[arg-type]
            with self.assertRaises(PolicyClientError):
                self.client.approval_status(bad)  # type: ignore[arg-type]
            with self.assertRaises(PolicyClientError):
                self.client.approve(bad, "bob")  # type: ignore[arg-type]
        for who in ("", "  ", None):
            with self.assertRaises(PolicyClientError):
                self.client.approve("ap-1", who)  # type: ignore[arg-type]
            with self.assertRaises(PolicyClientError):
                self.client.reject("ap-1", who)  # type: ignore[arg-type]
        with self.assertRaises(PolicyClientError):
            self.client.consume("ap-1", ["x"])  # type: ignore[arg-type]
        self.assertEqual(self.pm.requests, [])

    # -- construction / TLS ------------------------------------------------

    def test_http_url_refused_without_test_flag(self):
        with self.assertRaises(PolicyClientError) as cm:
            HttpPolicyClient("http://pm.local:8443", 5.0)
        self.assertEqual(cm.exception.kind, "config")

    def test_bad_urls_refused(self):
        for url in ("", "pm.local", "ftp://pm.local", "https://", "https://pm.local/?x=1"):
            with self.assertRaises(PolicyClientError) as cm:
                HttpPolicyClient(url, 5.0)
            self.assertEqual(cm.exception.kind, "config", url)

    def test_trailing_slash_stripped(self):
        c = HttpPolicyClient("https://pm.local:8443/", 5.0)
        self.assertEqual(c.base_url, "https://pm.local:8443")

    def test_unusable_mtls_material_fails_closed_on_first_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert = os.path.join(tmp, "c.pem")
            key = os.path.join(tmp, "k.pem")
            ca = os.path.join(tmp, "ca.pem")
            for p in (cert, key, ca):
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write("not a pem\n")
            c = HttpPolicyClient("https://127.0.0.1:1", 0.5, cert, key, ca)
            with self.assertRaises(PolicyClientError) as cm:
                c.decide({})
            self.assertEqual(cm.exception.kind, "tls")
            self.assertNotIn("not a pem", str(cm.exception))

    def test_missing_mtls_files_fail_closed(self):
        c = HttpPolicyClient("https://127.0.0.1:1", 0.5, "/nonexistent/c.pem", "/nonexistent/k.pem", "")
        with self.assertRaises(PolicyClientError) as cm:
            c.decide({})
        self.assertEqual(cm.exception.kind, "tls")


class PolicyDecisionTest(unittest.TestCase):
    def test_from_response_rejects_non_dict(self):
        for bad in (None, "ALLOW", 1, [EXAMPLE_DECISION]):
            with self.assertRaises(PolicyClientError):
                PolicyDecision.from_response(bad)

    def test_from_response_malformed_freigabe_id(self):
        bad = dict(EXAMPLE_DECISION, freigabe_id="../x")
        with self.assertRaises(PolicyClientError):
            PolicyDecision.from_response(bad)

    def test_from_response_keeps_raw(self):
        d = PolicyDecision.from_response(EXAMPLE_DECISION)
        self.assertEqual(d.raw, EXAMPLE_DECISION)


class StubPolicyClientTest(unittest.TestCase):
    def test_default_allows_and_records(self):
        stub = StubPolicyClient()
        d = stub.decide({"aktion": {"art": "add_case_note"}})
        self.assertEqual(d.gate, "ALLOW")
        self.assertEqual(stub.calls, [("decide", {"aktion": {"art": "add_case_note"}})])

    def test_scripted_error_is_raised(self):
        stub = StubPolicyClient(PolicyClientError("down", "unreachable"))
        with self.assertRaises(PolicyClientError):
            stub.decide({})

    def test_callable_decision(self):
        stub = StubPolicyClient(lambda req: PolicyDecision(
            entscheidung_id="pm-x", gate="DENY", code=req["kontext"]["why"]))
        d = stub.decide({"kontext": {"why": "NO_EVIDENCE"}})
        self.assertEqual((d.gate, d.code), ("DENY", "NO_EVIDENCE"))

    def test_unreachable_stub(self):
        stub = StubPolicyClient(reachable=False, approvals={"ap-1": {}})
        with self.assertRaises(PolicyClientError):
            stub.health()
        self.assertTrue(stub.halt_status().halted)  # unknown -> halted
        with self.assertRaises(PolicyClientError):
            stub.approve("ap-1", "bob")
        with self.assertRaises(PolicyClientError):
            stub.consume("ap-1", {})
        self.assertEqual(StubPolicyClient().health(), {"status": "ok"})

    def test_halt_consume_and_status(self):
        stub = StubPolicyClient(halted=True, approvals={"ap-1": {"status": "approved", "erteilt": 1}})
        self.assertTrue(stub.halt_status().halted)
        self.assertTrue(stub.approval_status("ap-1").approved)
        self.assertTrue(stub.consume("ap-1", {}).ok)
        self.assertEqual(stub.approval_status("ap-1").status, "consumed")
        self.assertEqual(stub.consume("ap-1", {}).code, CODE_CONSUMED)  # single use
        self.assertEqual(stub.consume("ap-9", {}).code, CODE_UNKNOWN_APPROVAL)
        stub2 = StubPolicyClient(consume_ok=False, approvals={"ap-2": {"status": "approved"}})
        self.assertEqual(stub2.consume("ap-2", {}).code, CODE_EXPIRED)
        with self.assertRaises(PolicyClientError):
            stub2.consume("../x", {})

    def test_stub_approval_lifecycle_mirrors_embedded_client(self):
        stub = StubPolicyClient(approvals={"ap-1": {"noetig": 2, "initiator": "alice"}})
        self.assertEqual(stub.consume("ap-1", {}).code, CODE_NOT_APPROVED)
        self.assertEqual(stub.approve("ap-1", "alice").code, CODE_SELF_APPROVAL)
        st = stub.approve("ap-1", "bob")
        self.assertEqual((st.status, st.erteilt, st.noetig, st.code), ("pending", 1, 2, None))
        self.assertEqual(stub.approve("ap-1", "bob").code, CODE_DUPLICATE)
        st = stub.approve("ap-1", "carol")
        self.assertEqual((st.status, st.erteilt), ("approved", 2))
        self.assertTrue(stub.consume("ap-1", {}).ok)
        self.assertEqual([c[0] for c in stub.calls],
                         ["consume", "approve", "approve", "approve", "approve", "consume"])

    def test_stub_halt_blocks_approve_and_agent_consume(self):
        stub = StubPolicyClient(halted=True, approvals={"ap-1": {}, "ap-2": {"status": "approved", "principal": "agent"}})
        self.assertEqual(stub.approve("ap-1", "bob").code, CODE_HALTED)
        self.assertEqual(stub.consume("ap-2", {}).code, CODE_HALTED)
        self.assertEqual(stub.approval_status("ap-2").status, "expired")

    def test_stub_reject(self):
        stub = StubPolicyClient(approvals={"ap-1": {}})
        self.assertEqual(stub.reject("ap-1", "bob").status, "rejected")
        self.assertEqual(stub.approve("ap-1", "carol").code, CODE_NOT_APPROVED)


class ApprovalRefTest(unittest.TestCase):
    def test_ref_is_sha256_prefix_like_the_policy_manager(self):
        self.assertEqual(approval_ref("ap-1"), hashlib.sha256(b"ap-1").hexdigest()[:16])
        self.assertEqual(len(approval_ref("ap-5521")), 16)
        self.assertEqual(approval_ref(""), "-")
        self.assertEqual(approval_ref(None), "-")

    def test_redact_path_replaces_ids_only_inside_approval_paths(self):
        ref = approval_ref("ap-1")
        self.assertEqual(redact_path("POST /v1/approvals/ap-1/consume -> HTTP 409"),
                         f"POST /v1/approvals/#{ref}/consume -> HTTP 409")
        self.assertEqual(redact_path("GET /v1/approvals/ap-1"), f"GET /v1/approvals/#{ref}")
        self.assertEqual(redact_path("POST /v1/decide -> HTTP 500"), "POST /v1/decide -> HTTP 500")
        self.assertEqual(redact_path("GET /v1/halt"), "GET /v1/halt")


class BuildPolicyClientTest(unittest.TestCase):
    def test_legacy_mode_returns_none(self):
        self.assertIsNone(build_policy_client(McpServerConfig()))

    def test_invalid_mode_returns_none(self):
        cfg = McpServerConfig(policy_mode="embedded", policy_service_url="https://pm.local")
        self.assertIsNone(build_policy_client(cfg))
        cfg = McpServerConfig(policy_mode="service")  # no URL
        self.assertIsNone(build_policy_client(cfg))

    def test_service_mode_returns_http_client_with_config(self):
        cfg = McpServerConfig(policy_mode="service", policy_service_url="https://pm.local:8443/",
                              policy_timeout_s=2.5, policy_client_cert="/c.pem",
                              policy_client_key="/k.pem", policy_ca="/ca.pem")
        c = build_policy_client(cfg)
        self.assertIsInstance(c, HttpPolicyClient)
        self.assertEqual(c.base_url, "https://pm.local:8443")
        self.assertEqual(c.timeout_s, 2.5)
        self.assertEqual((c.client_cert, c.client_key, c.ca), ("/c.pem", "/k.pem", "/ca.pem"))

    def test_service_mode_with_http_url_raises_config_error(self):
        cfg = McpServerConfig(policy_mode="service", policy_service_url="http://pm.local")
        with self.assertRaises(PolicyClientError) as cm:
            build_policy_client(cfg)
        self.assertEqual(cm.exception.kind, "config")


if __name__ == "__main__":
    unittest.main()
