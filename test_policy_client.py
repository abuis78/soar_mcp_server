"""Contract tests for policy/client.py (SPEC-MCP Phase 2.2, MCP-09).

A local plain-HTTP server plays the Policy Manager. TLS is not exercised
here (no certificates in the repo, L8); the mTLS path is covered up to the
SSL-context construction with unusable dummy files.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from policy.client import (
    HttpPolicyClient,
    PolicyClientError,
    PolicyDecision,
    StubPolicyClient,
    build_policy_client,
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
        self.pm.route("POST", "/v1/decide", 200, {"gate": "ALLOW"})
        with self.assertRaises(PolicyClientError) as cm:
            self.client.decide({})
        self.assertEqual(cm.exception.kind, "contract")

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
        self.pm.route("GET", "/v1/halt", 200, {"halted": True})
        self.assertTrue(self.client.halt_status())
        self.pm.route("GET", "/v1/halt", 200, {"halted": False})
        self.assertFalse(self.client.halt_status())

    def test_halt_status_unknown_counts_as_halted(self):
        self.pm.route("GET", "/v1/halt", 500, {"error": "x"})
        self.assertTrue(self.client.halt_status())
        self.pm.route("GET", "/v1/halt", 200, {"state": "running"})
        self.assertTrue(self.client.halt_status())
        self.pm.route("GET", "/v1/halt", 200, {"halted": "no"})
        self.assertTrue(self.client.halt_status())

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
        self.pm.route("GET", "/v1/approvals/ap-5521", 200, {"freigabe_id": "ap-5521", "status": "approved"})
        self.pm.route("POST", "/v1/approvals/ap-5521/consume", 200, {"freigabe_id": "ap-5521", "consumed": True})
        self.assertEqual(self.client.approval_status("ap-5521")["status"], "approved")
        self.assertTrue(self.client.consume("ap-5521")["consumed"])
        self.assertEqual([r[:2] for r in self.pm.requests],
                         [("GET", "/v1/approvals/ap-5521"), ("POST", "/v1/approvals/ap-5521/consume")])

    def test_consume_failure_raises(self):
        self.pm.route("POST", "/v1/approvals/ap-1/consume", 409, {"error": "expired"})
        with self.assertRaises(PolicyClientError) as cm:
            self.client.consume("ap-1")
        self.assertEqual(cm.exception.kind, "http")

    def test_malformed_freigabe_id_never_hits_the_wire(self):
        for bad in ("../admin/halt", "ap 1", "", "a" * 200, None):
            with self.assertRaises(PolicyClientError):
                self.client.consume(bad)  # type: ignore[arg-type]
            with self.assertRaises(PolicyClientError):
                self.client.approval_status(bad)  # type: ignore[arg-type]
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
        stub = StubPolicyClient(reachable=False)
        with self.assertRaises(PolicyClientError):
            stub.health()
        self.assertTrue(stub.halt_status())  # unknown -> halted
        self.assertEqual(StubPolicyClient().health(), {"status": "ok"})

    def test_halt_consume_and_status(self):
        stub = StubPolicyClient(halted=True, approvals={"ap-1": {"status": "approved"}})
        self.assertTrue(stub.halt_status())
        self.assertEqual(stub.approval_status("ap-1")["status"], "approved")
        self.assertTrue(stub.consume("ap-1")["consumed"])
        with self.assertRaises(PolicyClientError):
            stub.approval_status("ap-1")  # consumed -> gone
        stub2 = StubPolicyClient(consume_ok=False)
        with self.assertRaises(PolicyClientError):
            stub2.consume("ap-2")
        with self.assertRaises(PolicyClientError):
            stub2.consume("../x")


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
