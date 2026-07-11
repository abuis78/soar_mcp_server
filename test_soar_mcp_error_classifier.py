"""Tests for the REST/COA error classifier (issue #70)."""
from __future__ import annotations

import unittest

import requests

from soar_mcp_tools import classify_exception, classify_response


class _FakeResp:
    def __init__(self, status_code, url="https://soar.example.com/rest/container/5", body=None, text="raw"):
        self.status_code = status_code
        self.url = url
        self._body = body
        self.text = text

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class ClassifyResponseTest(unittest.TestCase):
    def test_401_authentication(self):
        i = classify_response(_FakeResp(401))
        self.assertEqual(i["category"], "authentication")
        self.assertIn("401", i["safe_message"])
        self.assertIn("ph-auth-token", i["suggested_next_step"])

    def test_403_authorization(self):
        i = classify_response(_FakeResp(403))
        self.assertEqual(i["category"], "authorization")
        self.assertIn("403", i["safe_message"])

    def test_404_not_found(self):
        i = classify_response(_FakeResp(404))
        self.assertEqual(i["category"], "not_found")

    def test_500_server_error(self):
        i = classify_response(_FakeResp(503))
        self.assertEqual(i["category"], "server_error")

    def test_endpoint_category_extracted(self):
        i = classify_response(_FakeResp(404, url="https://x/rest/playbook/9/export"))
        self.assertEqual(i["endpoint_category"], "rest/playbook")

    def test_soar_message_included_but_not_raw_text(self):
        i = classify_response(_FakeResp(400, body={"message": "bad scm_id"}, text="<html>secret</html>"))
        self.assertIn("bad scm_id", i["safe_message"])
        self.assertNotIn("secret", i["safe_message"])

    def test_raw_text_never_leaks_when_no_json(self):
        i = classify_response(_FakeResp(400, body=None, text="<html>TOKEN=abc</html>"))
        self.assertNotIn("abc", i["safe_message"])


class ClassifyExceptionTest(unittest.TestCase):
    def test_timeout(self):
        i = classify_exception(requests.exceptions.Timeout())
        self.assertEqual(i["category"], "timeout")
        self.assertIn("timed out", i["safe_message"])

    def test_ssl(self):
        i = classify_exception(requests.exceptions.SSLError())
        self.assertEqual(i["category"], "tls")
        self.assertIn("SSL error", i["safe_message"])

    def test_connection(self):
        i = classify_exception(requests.exceptions.ConnectionError(), where="COA endpoint")
        self.assertEqual(i["category"], "connection")
        self.assertIn("Connection error", i["safe_message"])
        self.assertIn("COA endpoint", i["safe_message"])

    def test_unknown(self):
        i = classify_exception(RuntimeError("x"))
        self.assertEqual(i["category"], "unknown")


if __name__ == "__main__":
    unittest.main()
