"""Tests for the structured response envelope (issue #74)."""
from __future__ import annotations

import json
import unittest

from soar_mcp_envelope import (
    envelope_response,
    make_envelope,
    normalize_output_format,
    render_envelope,
)


class EnvelopeTest(unittest.TestCase):
    def test_make_envelope_defaults(self):
        e = make_envelope(True, "done")
        self.assertEqual(e, {"ok": True, "summary": "done", "data": {}, "findings": [], "errors": []})

    def test_normalize_output_format(self):
        self.assertEqual(normalize_output_format("JSON"), "json")
        self.assertEqual(normalize_output_format("bogus"), "text")
        self.assertEqual(normalize_output_format(None), "text")
        self.assertEqual(normalize_output_format("json", default="json"), "json")

    def test_render_json_roundtrips(self):
        e = make_envelope(False, "nope", data={"x": 1}, errors=["boom"])
        out = render_envelope(e, "json")
        parsed = json.loads(out)
        self.assertEqual(parsed["ok"], False)
        self.assertEqual(parsed["data"], {"x": 1})
        self.assertEqual(parsed["errors"], ["boom"])

    def test_render_text_has_markers_and_sections(self):
        e = make_envelope(
            True, "all good",
            findings=[{"severity": "warn", "message": "watch out"}],
            data={"k": "v"},
        )
        out = render_envelope(e, "text")
        self.assertIn("✅ all good", out)
        self.assertIn("[WARN] watch out", out)
        self.assertIn("Data:", out)

    def test_render_text_failure_marker(self):
        out = render_envelope(make_envelope(False, "failed"), "text")
        self.assertTrue(out.startswith("❌ failed"))

    def test_envelope_response_convenience(self):
        out = envelope_response(True, "ok", data={"a": 1}, fmt="json")
        self.assertEqual(json.loads(out)["summary"], "ok")

    def test_errors_dict_uses_safe_message(self):
        out = render_envelope(
            make_envelope(False, "x", errors=[{"safe_message": "auth failed", "message": "raw"}]),
            "text",
        )
        self.assertIn("auth failed", out)
        self.assertNotIn("raw", out)


if __name__ == "__main__":
    unittest.main()
