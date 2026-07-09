"""
SOAR MCP Server — Shared Utilities

Provides recursive audit redaction and other helpers shared across
soar_mcp_tools.py, soar_mcp_handler.py, and future tool modules.

Copyright 2026 Andreas Buis
"""
from __future__ import annotations

from typing import Any

# Keys whose values are always redacted, regardless of nesting depth.
_SENSITIVE_KEYS: frozenset[str] = frozenset({
    "archive_b64",
    "playbook",
    "bound_soar_auth_token",
    "ph-auth-token",
    "ph_auth_token",
    "auth_token",
    "token",
    "password",
    "secret",
    "api_key",
    "apikey",
    "auth",
    "credential",
    "private_key",
})

_REDACTED = "<redacted>"
_MAX_STR_LEN = 500


def redact_nested(obj: Any, *, depth: int = 0, max_depth: int = 10) -> Any:
    """
    Recursively walk obj and redact values whose key matches _SENSITIVE_KEYS.

    - Dicts: redact matching keys; recurse into non-matching values.
    - Lists/tuples: recurse into each element.
    - Strings longer than _MAX_STR_LEN: truncate with a length note.
    - All other scalars: return as-is.
    - Depth limit prevents infinite recursion on circular-like structures.
    """
    if depth > max_depth:
        return _REDACTED

    if isinstance(obj, dict):
        result: dict = {}
        for k, v in obj.items():
            if isinstance(k, str) and k.lower() in _SENSITIVE_KEYS:
                result[k] = _REDACTED
            else:
                result[k] = redact_nested(v, depth=depth + 1, max_depth=max_depth)
        return result

    if isinstance(obj, (list, tuple)):
        redacted = [redact_nested(item, depth=depth + 1, max_depth=max_depth) for item in obj]
        return type(obj)(redacted)

    if isinstance(obj, (bytes, bytearray)):
        return f"<binary {len(obj)} bytes>"

    if isinstance(obj, str) and len(obj) > _MAX_STR_LEN:
        return obj[:_MAX_STR_LEN] + f"…<truncated, original_len={len(obj)}>"

    return obj
