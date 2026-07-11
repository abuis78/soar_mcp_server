"""
SOAR MCP Server — Structured Response Envelope (issue #74)

A common response shape for tools that opt into structured output, plus a
renderer that produces either human-readable text (the default, for interactive
use) or JSON (for agents/automation).

Envelope shape:
    {
        "ok":       bool,             # overall success
        "summary":  str,              # one-line human summary
        "data":     dict | list,      # tool-specific payload
        "findings": list[dict],       # severity-tagged findings (optional)
        "errors":   list[dict|str],   # error records (optional)
    }

The MCP handler already derives `isError` from `ok is False` or a non-empty
`errors` list (soar_mcp_handler._is_tool_error), so envelope tools integrate
with MCP error semantics without extra wiring.

Migration is incremental: new tools use this first; legacy text tools keep their
current behaviour until migrated. `output_format` ("text" | "json") lets a caller
choose per-call.

Copyright 2026 Andreas Buis
"""
from __future__ import annotations

import json
from typing import Any, Optional

_VALID_FORMATS = ("text", "json")


def make_envelope(
    ok: bool,
    summary: str,
    *,
    data: Any = None,
    findings: Optional[list] = None,
    errors: Optional[list] = None,
) -> dict:
    """Build a canonical response envelope."""
    return {
        "ok": bool(ok),
        "summary": str(summary),
        "data": data if data is not None else {},
        "findings": list(findings) if findings else [],
        "errors": list(errors) if errors else [],
    }


def normalize_output_format(value: Any, default: str = "text") -> str:
    """Coerce a caller-supplied output_format to a valid value."""
    v = str(value or default).strip().lower()
    return v if v in _VALID_FORMATS else default


def render_envelope(envelope: dict, fmt: str = "text") -> str:
    """Render an envelope as JSON or human-readable text."""
    fmt = normalize_output_format(fmt)
    if fmt == "json":
        return json.dumps(envelope, indent=2, default=str)

    ok = envelope.get("ok")
    lines = [f"{'✅' if ok else '❌'} {envelope.get('summary', '')}".rstrip()]

    findings = envelope.get("findings") or []
    if findings:
        lines.append("")
        lines.append("Findings:")
        for f in findings:
            if isinstance(f, dict):
                sev = str(f.get("severity", "info")).upper()
                msg = f.get("message") or f.get("summary") or f.get("code") or str(f)
                lines.append(f"  [{sev}] {msg}")
            else:
                lines.append(f"  - {f}")

    errors = envelope.get("errors") or []
    if errors:
        lines.append("")
        lines.append("Errors:")
        for e in errors:
            if isinstance(e, dict):
                lines.append(f"  - {e.get('safe_message') or e.get('message') or e}")
            else:
                lines.append(f"  - {e}")

    data = envelope.get("data")
    if data:
        lines.append("")
        lines.append("Data:")
        lines.append(json.dumps(data, indent=2, default=str))

    return "\n".join(lines)


def envelope_response(
    ok: bool,
    summary: str,
    *,
    data: Any = None,
    findings: Optional[list] = None,
    errors: Optional[list] = None,
    fmt: str = "text",
) -> str:
    """Convenience: build + render in one call. Returns the string a tool returns."""
    env = make_envelope(ok, summary, data=data, findings=findings, errors=errors)
    return render_envelope(env, fmt)
