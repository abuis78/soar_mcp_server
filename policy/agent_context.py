"""Agent context for write-tool calls (SPEC-MCP MCP-W07, concept OQ-12).

An agent run that asks for a write action must bring its evidence and its
judgement along (design decisions D22 / D23). Instead of six loose arguments
every write tool accepts ONE optional object::

    agent_context: {
        lauf_id:      "r-8812",                    # run id of the agent run
        stufe:        3,                           # escalation stage 0-4 (PM-F03)
        domaene:      "cyber",                     # cyber | physisch | kognitiv
        tipping_off:  "laut",                      # laut | leise (PM-F04)
        beleg_ids:    ["tb-2026-10-17-000231"],    # evidence ids, e.g. Tool Broker aufruf_id
        urteil: {                                  # the agent's judgement
            empfehlung:     "...",
            gegenargumente: ["..."],
            unsicherheiten: ["..."],
            konfidenz:      0.72                   # 0..1 (MCP-W05: the only confidence source)
        }
    }

Wire names are the spec names on purpose (Runtime concept E7). Python code
is English (L13).

This module only validates and normalises. Whether the object is required
depends on the caller: for ``principal_type = agent`` it is (NO_EVIDENCE /
INCOMPLETE_JUDGEMENT mirror the Policy Manager's own refusal, PM §9); for
humans and brokers it is optional but, when present, must be well-formed.

ASSUMPTION: the ``domaene`` value set comes from the design document §7
(cyber / physisch / kognitiv); the Policy Manager spec shows only ``cyber``.
"""

from __future__ import annotations

from typing import Any, Optional

# Refusal codes (PM spec §9 names the first two; the third is app-local).
NO_EVIDENCE = "NO_EVIDENCE"
INCOMPLETE_JUDGEMENT = "INCOMPLETE_JUDGEMENT"
INVALID_AGENT_CONTEXT = "INVALID_AGENT_CONTEXT"

DOMAENEN: tuple[str, ...] = ("cyber", "physisch", "kognitiv")
TIPPING_OFF: tuple[str, ...] = ("laut", "leise")
STUFE_MIN, STUFE_MAX = 0, 4

# Size limits: the object travels into audit lines and to the Policy Manager.
MAX_ID_LEN = 128
MAX_TEXT_LEN = 2000
MAX_LIST_ITEMS = 50

AGENT_CONTEXT_SCHEMA: dict = {
    "type": "object",
    "description": (
        "Agent-run context (SPEC-MCP MCP-W07). REQUIRED when the calling MCP token "
        "has principal_type 'agent' and the Policy Manager decides this call: "
        "beleg_ids (evidence) and a complete urteil (judgement, decision W14) are "
        "mandatory: empfehlung (non-empty), gegenargumente and unsicherheiten (each a "
        "list with at least one non-empty entry; never an empty list - write "
        "'keine erkannt' if nothing was found) and konfidenz (0..1). Otherwise the "
        "call is refused with NO_EVIDENCE / INCOMPLETE_JUDGEMENT. Optional for human tokens."
    ),
    "properties": {
        "lauf_id": {"type": "string", "maxLength": MAX_ID_LEN,
                    "description": "Id of the agent run (audit correlation)."},
        "stufe": {"type": "integer", "minimum": STUFE_MIN, "maximum": STUFE_MAX,
                  "description": "Escalation stage from the decision matrix (0-4)."},
        "domaene": {"type": "string", "enum": list(DOMAENEN),
                    "description": "Domain of the situation."},
        "tipping_off": {"type": "string", "enum": list(TIPPING_OFF),
                        "description": "Whether the action is noisy (laut) or quiet (leise)."},
        "beleg_ids": {"type": "array", "items": {"type": "string", "maxLength": MAX_ID_LEN},
                      "maxItems": MAX_LIST_ITEMS,
                      "description": "Evidence ids backing the request (e.g. Tool Broker aufruf_id)."},
        "urteil": {
            "type": "object",
            "description": "The agent's judgement (D23).",
            "properties": {
                "empfehlung": {"type": "string", "maxLength": MAX_TEXT_LEN,
                               "description": "Recommended action (required for agents, non-empty)."},
                "gegenargumente": {"type": "array", "items": {"type": "string", "maxLength": MAX_TEXT_LEN},
                                   "maxItems": MAX_LIST_ITEMS,
                                   "description": "Counter-arguments (required for agents, at least one "
                                                  "non-empty entry, e.g. 'keine erkannt')."},
                "unsicherheiten": {"type": "array", "items": {"type": "string", "maxLength": MAX_TEXT_LEN},
                                   "maxItems": MAX_LIST_ITEMS,
                                   "description": "Uncertainties (required for agents, at least one "
                                                  "non-empty entry, e.g. 'keine erkannt')."},
                "konfidenz": {"type": "number", "minimum": 0, "maximum": 1,
                              "description": "Confidence 0..1 (required for agents)."},
            },
            "additionalProperties": False,
        },
    },
    "additionalProperties": False,
}

_TOP_KEYS = frozenset(AGENT_CONTEXT_SCHEMA["properties"])
_URTEIL_KEYS = frozenset(AGENT_CONTEXT_SCHEMA["properties"]["urteil"]["properties"])


class _Invalid(Exception):
    pass


def _str(value: object, name: str, max_len: int) -> str:
    if not isinstance(value, str):
        raise _Invalid(f"{name} must be a string")
    value = value.strip()
    if not value:
        raise _Invalid(f"{name} must not be empty")
    if len(value) > max_len:
        raise _Invalid(f"{name} longer than {max_len} characters")
    return value


def _str_list(value: object, name: str, max_len: int) -> list[str]:
    if not isinstance(value, list):
        raise _Invalid(f"{name} must be a list of strings")
    if len(value) > MAX_LIST_ITEMS:
        raise _Invalid(f"{name} has more than {MAX_LIST_ITEMS} items")
    return [_str(v, f"{name}[{i}]", max_len) for i, v in enumerate(value)]


def _non_empty(value: object) -> bool:
    """W14: a non-blank string, or a list with at least one non-blank entry."""
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return any(isinstance(v, str) and v.strip() for v in value)
    return False


def _validate_urteil(raw: object) -> dict:
    if not isinstance(raw, dict):
        raise _Invalid("urteil must be an object")
    unknown = set(raw) - _URTEIL_KEYS
    if unknown:
        raise _Invalid(f"urteil has unknown fields: {sorted(unknown)}")
    out: dict[str, Any] = {}
    if "empfehlung" in raw:
        out["empfehlung"] = _str(raw["empfehlung"], "urteil.empfehlung", MAX_TEXT_LEN)
    for key in ("gegenargumente", "unsicherheiten"):
        if key in raw:
            out[key] = _str_list(raw[key], f"urteil.{key}", MAX_TEXT_LEN)
    if "konfidenz" in raw:
        k = raw["konfidenz"]
        if isinstance(k, bool) or not isinstance(k, (int, float)):
            raise _Invalid("urteil.konfidenz must be a number between 0 and 1")
        if not 0.0 <= float(k) <= 1.0:
            raise _Invalid("urteil.konfidenz must be between 0 and 1")
        out["konfidenz"] = float(k)
    return out


def validate_agent_context(raw: object, *, required: bool) -> tuple[Optional[dict], Optional[str]]:
    """Validate and normalise an ``agent_context`` argument.

    Returns ``(context, None)`` on success (``context`` is None when the
    argument is absent and not required) or ``(None, code)`` where ``code`` is
    NO_EVIDENCE, INCOMPLETE_JUDGEMENT or INVALID_AGENT_CONTEXT. The reason text
    is available via :func:`describe_agent_context_error`.
    """
    ctx, code, _ = _validate(raw, required=required)
    return ctx, code


def describe_agent_context_error(raw: object, *, required: bool) -> str:
    """Human-readable reason for a failed validation (empty when valid)."""
    _, _, reason = _validate(raw, required=required)
    return reason


def _validate(raw: object, *, required: bool) -> tuple[Optional[dict], Optional[str], str]:
    if raw is None:
        if required:
            return None, NO_EVIDENCE, "agent_context is required for agent tokens (beleg_ids + urteil)"
        return None, None, ""
    if not isinstance(raw, dict):
        return None, INVALID_AGENT_CONTEXT, "agent_context must be an object"
    unknown = set(raw) - _TOP_KEYS
    if unknown:
        return None, INVALID_AGENT_CONTEXT, f"agent_context has unknown fields: {sorted(unknown)}"
    out: dict[str, Any] = {}
    try:
        if "lauf_id" in raw:
            out["lauf_id"] = _str(raw["lauf_id"], "lauf_id", MAX_ID_LEN)
        if "stufe" in raw:
            st = raw["stufe"]
            if isinstance(st, bool) or not isinstance(st, int) or not STUFE_MIN <= st <= STUFE_MAX:
                raise _Invalid(f"stufe must be an integer {STUFE_MIN}-{STUFE_MAX}")
            out["stufe"] = st
        if "domaene" in raw:
            d = _str(raw["domaene"], "domaene", 32).lower()
            if d not in DOMAENEN:
                raise _Invalid(f"domaene must be one of {list(DOMAENEN)}")
            out["domaene"] = d
        if "tipping_off" in raw:
            t = _str(raw["tipping_off"], "tipping_off", 16).lower()
            if t not in TIPPING_OFF:
                raise _Invalid(f"tipping_off must be one of {list(TIPPING_OFF)}")
            out["tipping_off"] = t
        if "beleg_ids" in raw:
            out["beleg_ids"] = _str_list(raw["beleg_ids"], "beleg_ids", MAX_ID_LEN)
        if "urteil" in raw:
            out["urteil"] = _validate_urteil(raw["urteil"])
    except _Invalid as exc:
        return None, INVALID_AGENT_CONTEXT, str(exc)

    if required:
        if not out.get("beleg_ids"):
            return None, NO_EVIDENCE, "agent requests need at least one beleg_id (evidence)"
        urteil = out.get("urteil") or {}
        # Decision W14 (PolicyManager KONZEPT.md, D23): all four fields, no empty
        # list - the engine denies the same with INCOMPLETE_JUDGEMENT, so refuse
        # here where the agent can still correct it without an audit entry.
        missing = [k for k in ("empfehlung", "gegenargumente", "unsicherheiten", "konfidenz")
                   if k not in urteil]
        empty = [k for k in ("empfehlung", "gegenargumente", "unsicherheiten")
                 if k in urteil and not _non_empty(urteil[k])]
        if missing or empty:
            parts = []
            if missing:
                parts.append(f"missing {missing}")
            if empty:
                parts.append(f"empty {empty} (write 'keine erkannt' instead of an empty list)")
            return None, INCOMPLETE_JUDGEMENT, "urteil is " + "; ".join(parts)
    return out, None, ""


def lauf_id_from_arguments(arguments: object) -> Optional[str]:
    """``lauf_id`` for audit lines: ``agent_context.lauf_id`` first, then the
    Phase-1 top-level argument. No validation beyond type (audit only)."""
    if not isinstance(arguments, dict):
        return None
    ctx = arguments.get("agent_context")
    if isinstance(ctx, dict) and isinstance(ctx.get("lauf_id"), str) and ctx["lauf_id"].strip():
        return ctx["lauf_id"].strip()
    top = arguments.get("lauf_id")
    if isinstance(top, str) and top.strip():
        return top.strip()
    return None
