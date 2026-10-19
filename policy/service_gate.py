"""Policy Manager adapter for write tools, mode ``service`` (SPEC-MCP Phase 2.5).

Requirements covered: MCP-W01 (every write tool, every principal), MCP-W02
(adapter builds the request, translates the answer into today's ⛔ / ⏸
messages), MCP-W03 (case artifact values travel along), MCP-W04 (initiator),
MCP-W05 (agent confidence only from the judgement), MCP-W07 (agent_context),
MCP-G04 (no fallback), concept OQ-13 (dry-runs skip decide).

The decision logic lives in the Policy Manager. This module never decides
anything itself; the only local refusals are fail-closed ones (unusable
configuration, missing evidence/judgement for agent tokens, transport errors).

Request shape follows the PolicyManager spec §5 example. Fields marked
ASSUMPTION go beyond that example and must be confirmed against the real
service (PolicyManager P3):

    {
      "aktion":    {"art": <tool>, "ziel": {...ids...}, "parameter": {...},
                    "kategorie": ..., "playbook": ...},          # last two: run_playbook only
      "kontext":   {stufe, domaene, tipping_off, lauf_id, beleg_ids, urteil,
                    "agent_id": ..., "agent_konfidenz": ...,
                    "asset_werte": [...]},                        # ASSUMPTION: name of the artifact values list
      "initiator": {"principal_type", "token_id", "soar_user_id",
                    "agent_id", "legacy"}                         # ASSUMPTION: field name (AN-08 demands the content)
    }

Reversibility is never sent (AN-05).
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from policy.agent_context import describe_agent_context_error, validate_agent_context
from policy.client import PolicyClient, PolicyClientError, PolicyDecision, build_policy_client

logger = logging.getLogger("soar_mcp.policy")

# Tools whose dry-run form changes nothing (concept finding Z4, decision OQ-13).
DRY_RUN_TOOLS: frozenset[str] = frozenset({
    "save_playbook_layout_only",
    "create_custom_function_draft",
    "update_custom_function_draft",
})

# Arguments that belong to gates, never to the action itself.
_GATE_ARGS: frozenset[str] = frozenset({"agent_context", "approval_token", "confirm_token", "freigabe_id"})
# Correlation ids are context, not targets.
_NON_TARGET_IDS: frozenset[str] = frozenset({"lauf_id", "broker_aufruf_id"})

_MAX_BEGRUENDUNG = 5

# Client cache keyed on the connection parameters; tests may inject a client.
_client_cache: dict[tuple, PolicyClient] = {}
_client_override: Optional[PolicyClient] = None


def set_policy_client_override(client: Optional[PolicyClient]) -> None:
    """Tests and local development: use this client instead of the HTTP one."""
    global _client_override
    _client_override = client


def _get_client(config: Any) -> Optional[PolicyClient]:
    if _client_override is not None:
        return _client_override
    key = (
        getattr(config, "policy_service_url", ""),
        float(getattr(config, "policy_timeout_s", 5.0) or 5.0),
        getattr(config, "policy_client_cert", ""),
        getattr(config, "policy_client_key", ""),
        getattr(config, "policy_ca", ""),
    )
    client = _client_cache.get(key)
    if client is None:
        client = build_policy_client(config)
        if client is not None:
            _client_cache[key] = client
    return client


def is_dry_run(tool_name: str, arguments: dict) -> bool:
    """True when the call is a dry-run of a tool whose dry-run writes nothing."""
    if tool_name not in DRY_RUN_TOOLS:
        return False
    return bool((arguments or {}).get("dry_run", True))


def invalid_policy_mode_message() -> str:
    return ("⛔ Blocked by policy: policy_mode is invalid or unusable (mode 'service' needs "
            "policy_service_url; 'embedded' is reserved and not available). Every write tool "
            "is refused until the asset configuration is corrected. Read tools are unaffected.")


def build_decide_request(
    tool_name: str,
    arguments: dict,
    principal: Any,
    agent_ctx: Optional[dict],
    *,
    asset_values: Optional[list] = None,
    playbook: Optional[dict] = None,
) -> dict:
    """Assemble the /v1/decide body. Pure function, no I/O."""
    args = arguments or {}
    ziel = {k: v for k, v in args.items()
            if k.endswith("_id") and k not in _NON_TARGET_IDS and k not in _GATE_ARGS
            and isinstance(v, (int, str)) and not isinstance(v, bool)}
    parameter = {k: v for k, v in args.items() if k not in _GATE_ARGS}
    aktion: dict[str, Any] = {"art": tool_name, "ziel": ziel, "parameter": parameter}
    if tool_name == "run_playbook" and isinstance(playbook, dict):
        aktion["kategorie"] = playbook.get("category") or ""
        aktion["playbook"] = playbook.get("name") or ""

    kontext: dict[str, Any] = dict(agent_ctx or {})
    is_agent = bool(getattr(principal, "is_agent", False))
    if is_agent:
        kontext["agent_id"] = getattr(principal, "agent_id", None)
        # MCP-W05: the only confidence source for agents is the checked judgement.
        konf = (kontext.get("urteil") or {}).get("konfidenz")
        if konf is not None:
            kontext["agent_konfidenz"] = konf
    else:
        # Humans may still pass agent_confidence as today (run_playbook).
        ac = args.get("agent_confidence")
        if isinstance(ac, (int, float)) and not isinstance(ac, bool):
            kontext["agent_konfidenz"] = float(ac)
    kontext["asset_werte"] = list(asset_values or [])

    initiator = {
        "principal_type": getattr(principal, "principal_type", "mensch"),
        "token_id": getattr(principal, "token_id", None),
        "soar_user_id": getattr(principal, "soar_user_id", None),
        "agent_id": getattr(principal, "agent_id", None) if is_agent else None,
        "legacy": bool(getattr(principal, "legacy", principal is None)),
    }
    return {"aktion": aktion, "kontext": kontext, "initiator": initiator}


def _summarise(decision: PolicyDecision) -> str:
    parts = []
    for item in decision.begruendung[:_MAX_BEGRUENDUNG]:
        if isinstance(item, dict):
            regel = item.get("regel") or "?"
            gate = item.get("gate") or ""
            grund = item.get("grund") or ""
            parts.append(f"{regel}->{gate}" + (f" ({grund})" if grund else ""))
    return "; ".join(parts)


def _ident(principal: Any) -> str:
    af = getattr(principal, "audit_fields", None)
    return af() if callable(af) else "principal=legacy token_id=legacy agent_id=-"


def decide_write_tool(
    tool_name: str,
    arguments: dict,
    client: Any,
    config: Any,
    principal: Any,
    *,
    collect_values: Optional[Callable[[Any, Any, int], list]] = None,
) -> Optional[str]:
    """Ask the Policy Manager before a write tool runs (mode ``service``).

    Returns None to proceed (ALLOW, or dry-run) or the user-facing ⛔ / ⏸
    message. Never raises; every failure path returns a ⛔ message.
    ``collect_values(client, config, case_id) -> list`` gathers the case's
    artifact values (MCP-W03); it is injected to keep this module free of
    SOAR-API imports.
    """
    args = arguments or {}
    ident = _ident(principal)

    if is_dry_run(tool_name, args):
        logger.info("[soar_mcp.policy] service skip=dry_run tool=%s %s", tool_name, ident)
        return None

    is_agent = bool(getattr(principal, "is_agent", False))
    agent_ctx, code = validate_agent_context(args.get("agent_context"), required=is_agent)
    if code is not None:
        reason = describe_agent_context_error(args.get("agent_context"), required=is_agent)
        logger.info("[soar_mcp.policy] service refused=%s tool=%s %s reason=%s",
                    code, tool_name, ident, reason)
        return f"⛔ Blocked by policy ({code}): {reason}"
    if is_agent and "agent_confidence" in args:
        logger.info("[soar_mcp.policy] service note=agent_confidence_ignored tool=%s %s "
                    "(confidence is taken from urteil.konfidenz only, MCP-W05)", tool_name, ident)

    try:
        pm = _get_client(config)
    except PolicyClientError as exc:
        logger.error("[soar_mcp.policy] service client config error tool=%s %s: %s", tool_name, ident, exc)
        return f"⛔ Blocked by policy: Policy Manager client configuration error ({exc.reason})."
    if pm is None:  # mode is not service (caller should not have come here) -> fail-closed
        return invalid_policy_mode_message()

    # Context the Policy Manager needs from SOAR: playbook category/name for
    # run_playbook (as today) and the case's artifact values (MCP-W03). Both
    # best-effort: a lookup failure sends less context, never skips the decision.
    playbook = None
    if tool_name == "run_playbook":
        pid = args.get("playbook_id")
        if isinstance(pid, int) and pid > 0:
            try:
                pb, _err = client.get(f"playbook/{pid}")
                playbook = pb if isinstance(pb, dict) else None
            except Exception as exc:  # noqa: BLE001
                logger.warning("[soar_mcp.policy] service playbook lookup failed pid=%s: %s", pid, exc)
    asset_values: list = []
    case_id = args.get("case_id", args.get("container_id"))
    if collect_values is not None and isinstance(case_id, int) and not isinstance(case_id, bool) and case_id > 0:
        try:
            asset_values = list(collect_values(client, config, case_id) or [])
        except Exception as exc:  # noqa: BLE001
            logger.warning("[soar_mcp.policy] service enrichment failed case=%s: %s -> no values", case_id, exc)

    request = build_decide_request(tool_name, args, principal, agent_ctx,
                                   asset_values=asset_values, playbook=playbook)
    try:
        decision = pm.decide(request)
    except PolicyClientError as exc:
        logger.error("[soar_mcp.policy] service unavailable tool=%s %s kind=%s: %s",
                     tool_name, ident, exc.kind, exc.reason)
        return (f"⛔ Blocked by policy: Policy Manager unavailable ({exc.kind}: {exc.reason}). "
                "No fallback to the in-app policy layer (fail-closed). Nothing was executed.")
    except Exception as exc:  # noqa: BLE001 — never let a client bug open the gate
        logger.exception("[soar_mcp.policy] service client failure tool=%s %s", tool_name, ident)
        return (f"⛔ Blocked by policy: Policy Manager client failure ({type(exc).__name__}). "
                "Nothing was executed.")

    logger.info("[soar_mcp.policy] service decision gate=%s entscheidung_id=%s freigabe_id=%s code=%s "
                "tool=%s %s policy_version=%s",
                decision.gate, decision.entscheidung_id, decision.freigabe_id or "-",
                decision.code or "-", tool_name, ident, decision.policy_version or "-")

    if decision.gate == "ALLOW":
        return None
    summary = _summarise(decision)
    if decision.gate == "DENY":
        code_txt = f", {decision.code}" if decision.code else ""
        return (f"⛔ Blocked by policy (DENY{code_txt}): entscheidung_id={decision.entscheidung_id}."
                + (f" Reason: {summary}" if summary else ""))
    needed = decision.freigaben_noetig or (2 if decision.gate == "APPROVE_2PERSON" else 1)
    return (
        f"⏸ Approval required by policy — {needed} distinct approver(s) ({decision.gate}).\n"
        f"  entscheidung_id={decision.entscheidung_id}  freigabe_id={decision.freigabe_id}"
        + (f"  ablauf={decision.ablauf}" if decision.ablauf else "") + "\n"
        + (f"  Reason: {summary}\n" if summary else "")
        + "  Approval redemption (approve_action / consume) is not available yet in this "
          "version; the request is held and will NOT execute now."
    )
