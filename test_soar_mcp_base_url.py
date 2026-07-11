"""Tests for base_url normalization / resolution (MissingSchema regression fix)."""
from __future__ import annotations

import unittest

from soar_mcp_handler import SoarMcpRestHandler as H


class BaseUrlNormalizeTest(unittest.TestCase):
    def test_scheme_qualified_passthrough(self):
        self.assertEqual(H._normalize_base_url("https://soar.example.com/rest"),
                         "https://soar.example.com/rest")
        self.assertEqual(H._normalize_base_url("http://lab.local/"), "http://lab.local")

    def test_scheme_less_host_defaults_to_https(self):
        # This is the exact MissingSchema trigger observed on the live 8.5 box.
        self.assertEqual(H._normalize_base_url("www.soar4rookies.com/rest"),
                         "https://www.soar4rookies.com/rest")
        self.assertEqual(H._normalize_base_url("soar.internal"),
                         "https://soar.internal")

    def test_empty_stays_empty(self):
        self.assertEqual(H._normalize_base_url(""), "")
        self.assertEqual(H._normalize_base_url(None), "")

    def test_non_http_scheme_rejected(self):
        self.assertEqual(H._normalize_base_url("ftp://evil"), "")
        self.assertEqual(H._normalize_base_url("file:///etc/passwd"), "")

    def test_trailing_slash_stripped(self):
        self.assertEqual(H._normalize_base_url("https://x.com/rest/"), "https://x.com/rest")


class BaseUrlResolutionTest(unittest.TestCase):
    """Acceptance tests for #93: phantom.rest unavailable (as in this env, where
    `import phantom.rest` raises ModuleNotFoundError) must fall back to the
    admin-configured base_url — never to request headers."""

    def setUp(self):
        self._orig = H._read_configured_base_url

    def tearDown(self):
        H._read_configured_base_url = staticmethod(self._orig)

    def test_phantom_unavailable_configured_present(self):
        # phantom.rest import fails here; configured base_url must be used.
        H._read_configured_base_url = staticmethod(lambda: "https://soar.example.com")
        self.assertEqual(H._extract_base_url(object()), "https://soar.example.com")

    def test_phantom_unavailable_configured_scheme_less(self):
        H._read_configured_base_url = staticmethod(lambda: "www.soar4rookies.com")
        self.assertEqual(H._extract_base_url(object()), "https://www.soar4rookies.com")

    def test_phantom_unavailable_no_config_fails_closed(self):
        H._read_configured_base_url = staticmethod(lambda: "")
        # No trusted source → "" (handler then returns a clear error, not MissingSchema).
        self.assertEqual(H._extract_base_url(object()), "")

    def test_configured_reader_never_uses_request(self):
        # The fallback source is the connector-persisted config, not the request —
        # _extract_base_url takes only `request` and must not derive from it.
        captured = {}
        H._read_configured_base_url = staticmethod(lambda: captured.setdefault("called", True) and "" or "")
        H._extract_base_url(object())
        self.assertTrue(captured.get("called"))


if __name__ == "__main__":
    unittest.main()
