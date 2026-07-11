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


if __name__ == "__main__":
    unittest.main()
