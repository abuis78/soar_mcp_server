"""Policy Manager adapter for write tools, mode ``service`` (SPEC-MCP Phase 2.5).

Requirements covered: MCP-W01 (every write tool, every principal), MCP-W02
(adapter builds the request, translates the answer into today's ⛔ / ⏸
messages), MCP-W03 (case artifact values travel along), MCP-W04 (initiator),
MCP-W05 (agent confidence only from the judgement), MCP-W07 (agent_context),
MCP-G04 (no fallback), concept OQ-13 (dry-runs skip decide).

The decision logic lives in the Policy Manager. This module never decides
anything itself; the only local refusals are fail-closed ones (unusable
configuration, missing evidence/judgement for agent tokens, transport errors).

Request shape = ``policy_client.base.DecisionRequest.to_wire()`` (PolicyManager
repo, feature/p1-core @ c6851e7) on top of the PM spec §5 example:

    {
      "aktion":  {"art": <tool>, "kategorie": "", "playbook": "",      # category/name: run_playbook only
                  "ziel": ["case_id=3", ...], "parameter": {...}},
      "kontext": {"principal_type": mensch|agent|broker,
                  "initiator": <soar_user_id | agent_id | "">,       # "" = legacy token, no identity (OQ-7)
                  "agent_id": "", "lauf_id": "", "schritt_id": "",
                  "domaene": "", "tipping_off": "",
                  "beleg_ids": [...], "urteil": {...},
                  "artefakt_werte": [...],                           # case artifact values (MCP-W03)
                  ["stufe": 0-4], ["agent_konfidenz": 0-1]}
    }

Reversibility is never sent (AN-05).
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

from policy.agent_context import describe_agent_context_error, validate_agent_context
from policy.client import (PolicyClient, PolicyClientError, PolicyDecision, approval_ref,
                           build_policy_client)
from policy.held_actions import HeldAction, HeldActionStore

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
_MAX_APPROVAL_REASON = 500  # chars of the decision summary sent as begruendung_kurz

# Client cache keyed on the connection parameters; tests may inject a client.
_client_cache: dict[tuple, PolicyClient] = {}
_client_override: Optional[PolicyClient] = None


def set_policy_client_override(client: Optional[PolicyClient]) -> None:
    """Tests and local development: use this client instead of the HTTP one."""
    global _client_override
    _client_override = client


_held_store: Optional[HeldActionStore] = None
_held_store_override: Optional[HeldActionStore] = None


def set_held_store_override(store: Optional[HeldActionStore]) -> None:
    """Tests: use this store (e.g. in a temp dir) instead of local/held_actions.json."""
    global _held_store_override
    _held_store_override = store


def get_held_store() -> HeldActionStore:
    global _held_store
    if _held_store_override is not None:
        return _held_store_override
    if _held_store is None:
        _held_store = HeldActionStore()
    return _held_store


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
    """Assemble the /v1/decide body (``DecisionRequest.to_wire`` shape).
    Pure function, no I/O."""
    args = arguments or {}
    ziel = [f"{k}={v}" for k, v in args.items()
            if k.endswith("_id") and k not in _NON_TARGET_IDS and k not in _GATE_ARGS
            and isinstance(v, (int, str)) and not isinstance(v, bool)]
    parameter = {k: v for k, v in args.items() if k not in _GATE_ARGS}
    aktion: dict[str, Any] = {"art": tool_name, "kategorie": "", "playbook": "",
                              "ziel": ziel, "parameter": parameter}
    if tool_name == "run_playbook" and isinstance(playbook, dict):
        aktion["kategorie"] = playbook.get("category") or ""
        aktion["playbook"] = playbook.get("name") or ""

    ctx = agent_ctx or {}
    is_agent = bool(getattr(principal, "is_agent", False))
    kontext: dict[str, Any] = {
        "principal_type": getattr(principal, "principal_type", None) or "mensch",
        "initiator": principal_identity(principal),
        "agent_id": (getattr(principal, "agent_id", None) or "") if is_agent else "",
        "lauf_id": str(ctx.get("lauf_id") or ""),
        "schritt_id": "",
        "domaene": str(ctx.get("domaene") or ""),
        "tipping_off": str(ctx.get("tipping_off") or ""),
        "beleg_ids": list(ctx.get("beleg_ids") or []),
        "urteil": dict(ctx.get("urteil") or {}),
        "artefakt_werte": list(asset_values or []),
    }
    if ctx.get("stufe") is not None:
        kontext["stufe"] = ctx["stufe"]
    if is_agent:
        # MCP-W05: the only confidence source for agents is the checked judgement.
        konf = kontext["urteil"].get("konfidenz")
        if konf is not None:
            kontext["agent_konfidenz"] = konf
    else:
        # Humans may still pass agent_confidence as today (run_playbook).
        ac = args.get("agent_confidence")
        if isinstance(ac, (int, float)) and not isinstance(ac, bool):
            kontext["agent_konfidenz"] = float(ac)
    return {"aktion": aktion, "kontext": kontext}


def principal_identity(principal: Any) -> str:
    """The accountable identity the Policy Manager keys initiator exclusion and
    approvals on: the scoped token's ``soar_user_id`` for humans and brokers,
    ``agent_id`` for agents, "" for the legacy full token (OQ-7: no identity,
    never an approver; the Policy Manager answers NO_INITIATOR for holds)."""
    if principal is None:
        return ""
    if getattr(principal, "is_agent", False):
        return str(getattr(principal, "agent_id", None) or "")
    return str(getattr(principal, "soar_user_id", None) or "")


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
    start_approval: Optional[Callable[[Any, Any, int, dict], Optional[str]]] = None,
) -> Optional[str]:
    """Ask the Policy Manager before a write tool runs (mode ``service``).

    Returns None to proceed (ALLOW, or dry-run) or the user-facing ⛔ / ⏸
    message. Never raises; every failure path returns a ⛔ message.
    ``collect_values(client, config, case_id) -> list`` gathers the case's
    artifact values (MCP-W03); it is injected to keep this module free of
    SOAR-API imports. ``start_approval(client, config, case_id, inputs) ->
    None | error`` starts the approval playbook (proposal B, asset option
    ``approval_playbook``); injected for the same reason.
    """
    args = arguments or {}
    ident = _ident(principal)

    if is_dry_run(tool_name, args):
        logger.info("[soar_mcp.policy] service skip=dry_run tool=%s %s", tool_name, ident)
        return None

    if args.get("freigabe_id"):
        # Phase 3.3 (OQ-11 compatibility path): the re-call redeems a held action.
        return redeem_held_action(tool_name, args, config, principal, args["freigabe_id"])

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
    halted = _agent_halted(pm, principal, tool_name, ident)
    if halted is not None:
        return halted

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

    logger.info("[soar_mcp.policy] service decision gate=%s entscheidung_id=%s freigabe_ref=%s code=%s "
                "tool=%s %s policy_version=%s",
                decision.gate, decision.entscheidung_id, approval_ref(decision.freigabe_id),
                decision.code or "-", tool_name, ident, decision.policy_version or "-")

    if decision.gate == "ALLOW":
        return None
    summary = _summarise(decision)
    if decision.gate == "DENY":
        code_txt = f", {decision.code}" if decision.code else ""
        return (f"⛔ Blocked by policy (DENY{code_txt}): entscheidung_id={decision.entscheidung_id}."
                + (f" Reason: {summary}" if summary else ""))
    needed = decision.freigaben_noetig or (2 if decision.gate == "APPROVE_2PERSON" else 1)
    held = HeldAction.build(
        decision.freigabe_id or "", tool_name, args, request,
        entscheidung_id=decision.entscheidung_id, gate=decision.gate, noetig=needed,
        initiator=principal_identity(principal),
        principal_type=getattr(principal, "principal_type", None) or "mensch",
        ablauf=decision.ablauf,
    )
    try:
        get_held_store().put(held)
        stored = True
    except Exception as exc:  # noqa: BLE001 — the hold stands; only redemption is affected
        logger.error("[soar_mcp.policy] service held action not stored freigabe_ref=%s: %s",
                     approval_ref(decision.freigabe_id), type(exc).__name__)
        stored = False
    if stored:
        request_approval_in_soar(client, config, case_id, decision, tool_name, needed,
                                 request, summary, principal, start_approval)
    return hold_message(decision, tool_name, needed, summary, stored=stored)


def request_approval_in_soar(client: Any, config: Any, case_id: Any, decision: PolicyDecision,
                             tool_name: str, needed: int, request: dict, summary: str,
                             principal: Any,
                             start_approval: Optional[Callable[[Any, Any, int, dict], Optional[str]]]
                             ) -> Optional[bool]:
    """Start the approval playbook on the case (proposal B). Returns None when
    not attempted (option off, no freigabe_id or no case), True when started,
    False when the start failed. Never raises; the hold stands either way.
    The raw freigabe_id goes only into the playbook input, logs carry the ref."""
    name = str(getattr(config, "approval_playbook", "") or "").strip()
    fid = decision.freigabe_id
    if (not name or start_approval is None or not fid
            or decision.gate not in ("APPROVE_1CLICK", "APPROVE_2PERSON")
            or not isinstance(case_id, int) or isinstance(case_id, bool) or case_id <= 0):
        return None
    ziel = (request.get("aktion") or {}).get("ziel") or []
    inputs = {
        "freigabe_id": str(fid),
        "noetig": str(needed),
        "initiator": principal_identity(principal),
        "art": tool_name,
        "ziel": ",".join(str(z) for z in ziel),
        "begruendung_kurz": summary[:_MAX_APPROVAL_REASON],
        "ablauf": str(decision.ablauf or ""),
    }
    try:
        err = start_approval(client, config, case_id, inputs)
    except Exception as exc:  # noqa: BLE001 — the hold stands; only the notification is lost
        err = type(exc).__name__
    if err:
        logger.warning("[soar_mcp.policy] service approval playbook not started freigabe_ref=%s case=%s: %s",
                       approval_ref(fid), case_id, str(err).replace(str(fid), "#" + approval_ref(fid)))
        return False
    logger.info("[soar_mcp.policy] service approval playbook started freigabe_ref=%s case=%s",
                approval_ref(fid), case_id)
    return True


def _agent_halted(pm: PolicyClient, principal: Any, tool_name: str, ident: str) -> Optional[str]:
    """Emergency stop (MCP-W08, AC-09, PM-F30/F31, SPEC-MCP Phase 3.5): before an
    agent principal's write is decided or redeemed, GET /v1/halt. Halted or
    unknown state -> ⛔ HALTED without a decide round-trip. Humans, brokers and
    the legacy token are never checked here (PM-F33: people keep working). The
    state is never cached so a halt takes effect on the next call."""
    if not getattr(principal, "is_agent", False):
        return None
    try:
        status = pm.halt_status()
        halted, grund = bool(status.halted), str(getattr(status, "grund", "") or "")
    except Exception as exc:  # noqa: BLE001 — halt_status should never raise; treat as unknown
        halted, grund = True, f"halt state unknown ({type(exc).__name__})"
    if not halted:
        return None
    logger.warning("[soar_mcp.policy] service refused=HALTED tool=%s %s grund=%s", tool_name, ident, grund or "-")
    return (f"⛔ Blocked by policy (HALTED): the agent chain is in emergency stop"
            + (f" ({grund})" if grund else "") + ". Agent tokens cannot write or redeem approvals until the "
            "Policy Manager is resumed; human analysts are not affected. Nothing was executed.")


def _action_args(args: dict) -> dict:
    return {k: v for k, v in (args or {}).items() if k not in _GATE_ARGS}


# Policy Manager answers after which a held action can never be redeemed.
_FINAL_APPROVAL_STATES: frozenset[str] = frozenset({"rejected", "expired", "consumed"})
_FINAL_CONSUME_CODES: frozenset[str] = frozenset({"CONSUMED", "EXPIRED", "UNKNOWN_APPROVAL", "ACTION_CHANGED"})


def redeem_held_action(tool_name: str, args: dict, config: Any, principal: Any, freigabe_id: Any) -> Optional[str]:
    """Re-call with ``freigabe_id`` (MCP-W06, OQ-11, AC-05): execute the held
    action only after the Policy Manager reports it approved AND ``consume``
    answers ``gueltig``. Returns None to proceed or the ⛔ / ⏸ message. Never
    raises; every failure path refuses (fail-closed)."""
    ident = _ident(principal)
    fid = str(freigabe_id).strip()
    try:
        pm = _get_client(config)
    except PolicyClientError as exc:
        logger.error("[soar_mcp.policy] service client config error tool=%s %s: %s", tool_name, ident, exc)
        return f"⛔ Blocked by policy: Policy Manager client configuration error ({exc.reason})."
    if pm is None:
        return invalid_policy_mode_message()
    halted = _agent_halted(pm, principal, tool_name, ident)
    if halted is not None:
        return halted

    store = get_held_store()
    try:
        held = store.get(fid)
    except Exception as exc:  # noqa: BLE001
        logger.error("[soar_mcp.policy] service held store unreadable freigabe_ref=%s: %s", approval_ref(fid), type(exc).__name__)
        held = None
    if held is None:
        logger.info("[soar_mcp.policy] service redeem refused=UNKNOWN_HELD_ACTION freigabe_ref=%s tool=%s %s",
                    approval_ref(fid), tool_name, ident)
        return (f"⛔ No held action for freigabe_id={fid}: unknown, expired or already redeemed on this SOAR "
                f"host. Request the action again (call {tool_name} without freigabe_id). Nothing was executed.")
    if held.tool != tool_name or held.args != _action_args(args):
        logger.info("[soar_mcp.policy] service redeem refused=ACTION_CHANGED freigabe_ref=%s tool=%s held_tool=%s %s",
                    approval_ref(fid), tool_name, held.tool, ident)
        return (f"⛔ Blocked by policy (ACTION_CHANGED): freigabe_id={fid} was issued for {held.tool} with "
                "different arguments. A held action can only be redeemed with the same tool and the same "
                "arguments. Nothing was executed.")

    try:
        status = pm.approval_status(fid)
        if status.pending:
            noetig = status.noetig or held.noetig
            logger.info("[soar_mcp.policy] service redeem status=pending freigabe_ref=%s erteilt=%s noetig=%s tool=%s %s",
                        approval_ref(fid), status.erteilt, noetig, tool_name, ident)
            return (f"⏸ Approval pending ({status.erteilt}/{noetig}) for freigabe_id={fid} "
                    f"(entscheidung_id={held.entscheidung_id}). The remaining approver(s) must call "
                    f'approve_action(freigabe_id="{fid}"); then call {tool_name} again with freigabe_id, '
                    "or let the completing approve_action execute it. Nothing was executed.")
        if not status.approved:
            if status.status in _FINAL_APPROVAL_STATES:
                _forget(store, fid)
            logger.info("[soar_mcp.policy] service redeem refused=%s code=%s freigabe_ref=%s tool=%s %s",
                        status.status, status.code or "-", approval_ref(fid), tool_name, ident)
            return (f"⛔ Blocked by policy: approval {status.status}"
                    + (f" ({status.code})" if status.code else "")
                    + f" for freigabe_id={fid}. Request the action again. Nothing was executed.")
        result = pm.consume(fid, held.request)
    except PolicyClientError as exc:
        logger.error("[soar_mcp.policy] service unavailable on redeem freigabe_ref=%s tool=%s %s kind=%s: %s",
                     approval_ref(fid), tool_name, ident, exc.kind, exc.reason)
        return (f"⛔ Blocked by policy: Policy Manager unavailable ({exc.kind}: {exc.reason}). "
                "No fallback (fail-closed). Nothing was executed; the approval is untouched.")
    except Exception as exc:  # noqa: BLE001
        logger.exception("[soar_mcp.policy] service client failure on redeem freigabe_ref=%s %s", approval_ref(fid), ident)
        return (f"⛔ Blocked by policy: Policy Manager client failure ({type(exc).__name__}). "
                "Nothing was executed.")

    if not result.ok:
        if result.code in _FINAL_CONSUME_CODES:
            _forget(store, fid)
        logger.info("[soar_mcp.policy] service consume refused code=%s freigabe_ref=%s entscheidung_id=%s tool=%s %s",
                    result.code or "-", approval_ref(fid), held.entscheidung_id, tool_name, ident)
        return (f"⛔ Blocked by policy: consume refused ({result.code or 'no code'}) for freigabe_id={fid}. "
                "Nothing was executed." + (" Request the action again." if result.code in _FINAL_CONSUME_CODES else ""))
    _forget(store, fid)
    logger.info("[soar_mcp.policy] service redeemed freigabe_ref=%s entscheidung_id=%s gate=%s tool=%s "
                "initiator=%s %s", approval_ref(fid), held.entscheidung_id, held.gate, tool_name, held.initiator or "-", ident)
    return None


def approve_action(
    arguments: dict,
    client: Any,
    config: Any,
    principal: Any,
    *,
    dispatch: Callable[[str, dict], str],
) -> str:
    """Tool ``approve_action(freigabe_id)`` (MCP-W06, OQ-11/OQ-16, SPEC-MCP 3.4).

    Humans with a scoped MCP token only (principal_type = mensch, identity =
    token's soar_user_id). The approval itself is judged by the Policy Manager
    (initiator exclusion, duplicates, halt). The call that completes the
    approval redeems it (``consume``) and executes the held action via
    ``dispatch(tool, args)``; the result is returned to the approver.
    Never raises; every failure path refuses without executing.
    """
    from soar_mcp_config import POLICY_MODE_INVALID, POLICY_MODE_SERVICE, policy_effective_mode

    args = arguments or {}
    ident = _ident(principal)
    mode = policy_effective_mode(config)
    if mode == POLICY_MODE_INVALID:
        return invalid_policy_mode_message()
    if mode != POLICY_MODE_SERVICE:
        return ("ℹ️ approve_action needs policy_mode = service. In the default mode approvals work as "
                "before: each approver calls run_playbook again with the same arguments plus "
                "approval_token (freigabe_id is accepted as an alias). Nothing was executed.")
    fid = str(args.get("freigabe_id") or "").strip()
    if not fid:
        return "⛔ approve_action needs freigabe_id (from the ⏸ hold message). Nothing was executed."

    ptype = getattr(principal, "principal_type", None) or "mensch"
    approver = str(getattr(principal, "soar_user_id", None) or "").strip()
    if principal is None or getattr(principal, "legacy", True) or ptype != "mensch" or not approver:
        why = ("agent and broker tokens cannot approve" if ptype != "mensch"
               else "this call carries no scoped-token identity (legacy ph-auth-token)")
        logger.info("[soar_mcp.policy] approve_action refused=NO_APPROVER freigabe_ref=%s %s", approval_ref(fid), ident)
        return (f"⛔ approve_action is for human analysts with a scoped MCP token (principal_type = mensch, "
                f"identity = token): {why}. Mint a scoped MCP token per approver ('mint mcp token') and "
                "retry. Nothing was executed.")

    try:
        pm = _get_client(config)
    except PolicyClientError as exc:
        logger.error("[soar_mcp.policy] approve_action client config error %s: %s", ident, exc)
        return f"⛔ Blocked by policy: Policy Manager client configuration error ({exc.reason})."
    if pm is None:
        return invalid_policy_mode_message()

    store = get_held_store()
    try:
        held = store.get(fid)
    except Exception as exc:  # noqa: BLE001
        logger.error("[soar_mcp.policy] approve_action held store unreadable freigabe_ref=%s: %s", approval_ref(fid), type(exc).__name__)
        held = None
    if held is None:
        logger.info("[soar_mcp.policy] approve_action refused=UNKNOWN_HELD_ACTION freigabe_ref=%s approver=%s %s",
                    approval_ref(fid), approver, ident)
        return (f"⛔ No held action for freigabe_id={fid} on this SOAR host: unknown, expired or already "
                "redeemed. The requester must request the action again. Nothing was executed.")

    try:
        status = pm.approve(fid, approver)
    except PolicyClientError as exc:
        logger.error("[soar_mcp.policy] approve_action service unavailable freigabe_ref=%s %s kind=%s: %s",
                     approval_ref(fid), ident, exc.kind, exc.reason)
        return (f"⛔ Blocked by policy: Policy Manager unavailable ({exc.kind}: {exc.reason}). "
                "No fallback (fail-closed). Nothing was executed; the approval is untouched.")
    except Exception as exc:  # noqa: BLE001
        logger.exception("[soar_mcp.policy] approve_action client failure freigabe_ref=%s %s", approval_ref(fid), ident)
        return f"⛔ Blocked by policy: Policy Manager client failure ({type(exc).__name__}). Nothing was executed."

    noetig = status.noetig or held.noetig
    logger.info("[soar_mcp.policy] approve_action status=%s code=%s erteilt=%s noetig=%s freigabe_ref=%s "
                "entscheidung_id=%s approver=%s initiator=%s %s",
                status.status, status.code or "-", status.erteilt, noetig, approval_ref(fid), held.entscheidung_id,
                approver, held.initiator or "-", ident)
    head = f"freigabe_id={fid} (entscheidung_id={held.entscheidung_id}, held {held.tool})"
    if status.code == "SELF_APPROVAL":
        return (f"⏸ You ({approver}) requested this action and cannot approve it yourself "
                f"({status.erteilt}/{noetig}). A DIFFERENT SOAR user must approve {head}. Nothing was executed.")
    if status.code == "DUPLICATE":
        return (f"⏸ You ({approver}) already approved this action ({status.erteilt}/{noetig}). "
                f"A DIFFERENT SOAR user must provide the remaining approval for {head}. Nothing was executed.")
    if status.code == "HALTED":
        return (f"⛔ Blocked by policy (HALTED): the Policy Manager is in emergency stop; approvals are not "
                f"accepted for {head}. Nothing was executed.")
    if status.code and not status.approved:
        return (f"⛔ Blocked by policy: approval not counted ({status.code}, status {status.status}) for {head}. "
                "Nothing was executed.")
    if status.pending:
        remaining = max(0, noetig - status.erteilt)
        return (f"⏸ Approval recorded ({status.erteilt}/{noetig}) by {approver} for {head}. "
                f"{remaining} more distinct approver(s) required — they call "
                f'approve_action(freigabe_id="{fid}"). Nothing was executed.')
    if not status.approved:
        if status.status in _FINAL_APPROVAL_STATES:
            _forget(store, fid)
        return (f"⛔ Blocked by policy: approval {status.status} for {head}. The requester must request the "
                "action again. Nothing was executed.")

    # Fully approved: the held tool must still be enabled; nothing is consumed before that check.
    enabled = getattr(config, "enabled_tools", None)
    if enabled is not None and held.tool not in enabled:
        return (f"⛔ Approved, but tool '{held.tool}' is disabled in the asset configuration, so {head} "
                "cannot execute. Enable it, run Test Connectivity and call approve_action again. "
                "Nothing was executed; the approval is untouched.")
    try:
        result = pm.consume(fid, held.request)
    except PolicyClientError as exc:
        logger.error("[soar_mcp.policy] approve_action consume unavailable freigabe_ref=%s %s kind=%s: %s",
                     approval_ref(fid), ident, exc.kind, exc.reason)
        return (f"⛔ Blocked by policy: Policy Manager unavailable on consume ({exc.kind}: {exc.reason}). "
                "Nothing was executed; call approve_action again later.")
    except Exception as exc:  # noqa: BLE001
        logger.exception("[soar_mcp.policy] approve_action consume failure freigabe_ref=%s %s", approval_ref(fid), ident)
        return f"⛔ Blocked by policy: Policy Manager client failure ({type(exc).__name__}). Nothing was executed."
    if not result.ok:
        if result.code in _FINAL_CONSUME_CODES:
            _forget(store, fid)
        logger.info("[soar_mcp.policy] approve_action consume refused code=%s freigabe_ref=%s %s",
                    result.code or "-", approval_ref(fid), ident)
        return (f"⛔ Blocked by policy: consume refused ({result.code or 'no code'}) for {head}. "
                "Nothing was executed.")
    _forget(store, fid)
    logger.info("[soar_mcp.policy] approve_action executed tool=%s freigabe_ref=%s entscheidung_id=%s "
                "gate=%s approver=%s initiator=%s %s",
                held.tool, approval_ref(fid), held.entscheidung_id, held.gate, approver, held.initiator or "-", ident)
    try:
        out = dispatch(held.tool, dict(held.args))
    except Exception as exc:  # noqa: BLE001
        logger.exception("[soar_mcp.policy] approve_action dispatch failed tool=%s freigabe_ref=%s", held.tool, approval_ref(fid))
        out = f"Internal error executing tool '{held.tool}': {type(exc).__name__}"
    return (f"✅ Approved ({status.erteilt}/{noetig}) and executed {held.tool} — {head}, "
            f"approved by {approver}, requested by {held.initiator or 'unknown'}.\n{out}")


def _forget(store: HeldActionStore, fid: str) -> None:
    try:
        store.remove(fid)
    except Exception as exc:  # noqa: BLE001
        logger.warning("[soar_mcp.policy] service held action not removed freigabe_ref=%s: %s", approval_ref(fid), type(exc).__name__)


def hold_message(decision: PolicyDecision, tool_name: str, needed: int, summary: str = "", *,
                 stored: bool = True) -> str:
    fid = decision.freigabe_id
    text = (
        f"⏸ Approval required by policy — {needed} distinct approver(s) ({decision.gate}).\n"
        f"  entscheidung_id={decision.entscheidung_id}  freigabe_id={fid}"
        + (f"  ablauf={decision.ablauf}" if decision.ablauf else "") + "\n"
        + (f"  Reason: {summary}\n" if summary else "")
        + "  Nothing has been executed.\n"
    )
    if not stored:
        return text + ("  The held action could not be stored on the SOAR host; the approval cannot "
                       "be redeemed. Fix the app's local/ directory and request the action again.")
    two = "each of the required approvers" if needed >= 2 else "one approver"
    return text + (
        f"  Next: {two} (a human with a scoped MCP token, never the requester) calls\n"
        f'  approve_action(freigabe_id="{fid}"). The call that completes the approval redeems it\n'
        f"  (consume) and executes the held {tool_name}.\n"
        f'  Alternative: call {tool_name} again with the same arguments plus freigabe_id="{fid}"\n'
        "  once all approvals are in; it is redeemed and executed the same way."
    )


def probe_policy_manager(config: Any) -> dict:
    """Diagnostics (MCP-G06): mode, reachability and halt state of the Policy
    Manager. Side-effect free: GET /health, then GET /v1/halt. Outside mode
    ``service`` reachable/halted stay None. Never raises; errors are reported
    as their class only, never with response bodies.
    """
    from soar_mcp_config import POLICY_MODE_SERVICE, policy_effective_mode

    mode = policy_effective_mode(config)
    out: dict[str, Any] = {
        "mode": mode,
        "service_url_configured": bool(getattr(config, "policy_service_url", "")),
        "reachable": None,
        "halted": None,
        "error": None,
    }
    if mode != POLICY_MODE_SERVICE:
        return out
    try:
        pm = _get_client(config)
    except PolicyClientError as exc:
        out.update(reachable=False, error=exc.kind)
        return out
    if pm is None:
        out.update(reachable=False, error="config")
        return out
    try:
        pm.health()
        out["reachable"] = True
    except PolicyClientError as exc:
        out.update(reachable=False, error=exc.kind)
        return out
    except Exception as exc:  # noqa: BLE001
        out.update(reachable=False, error=type(exc).__name__)
        return out
    try:
        out["halted"] = bool(pm.halt_status().halted)
    except Exception as exc:  # noqa: BLE001
        out.update(halted=True, error=type(exc).__name__)  # PM-F31: unknown -> halted
    return out

