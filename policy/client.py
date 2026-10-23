"""Policy Manager client for soar_mcp_server (SPEC-MCP MCP-G02 / MCP-G04,
Anbindung AN-01 / AN-02 / AN-04, SPEC-MCP Phase 2.2, wire aligned in Phase 3.1).

This module is the transport layer only. It knows nothing about tools, cases
or gates' meaning; the adapter (``policy/service_gate.py``) builds the request
and translates the decision into the user-facing messages.

Wire contract: PolicyManager spec §5 plus the shared package
``policy_client.base`` (PolicyManager repo, branch feature/p1-core @ c6851e7,
P1.5 "PolicyClient interface and wire types"). Python names here follow the
wire names on purpose (Runtime concept E7: wire = spec names).

    POST /v1/decide                            -> PolicyDecision
    POST /v1/approvals/{freigabe_id}/approve   -> ApprovalStatus
    POST /v1/approvals/{freigabe_id}/reject    -> ApprovalStatus
    GET  /v1/approvals/{freigabe_id}           -> ApprovalStatus
    POST /v1/approvals/{freigabe_id}/consume   -> ConsumeResult (ok only on {"gueltig": true})
    GET  /v1/halt                              -> HaltStatus  ({"angehalten": bool, "grund": str})
    GET  /health                               -> dict        (PM spec §5 "Betrieb")

Fail-closed by design (AN-04, PM §9 "Policy Manager nicht erreichbar"):
every transport or contract failure raises :class:`PolicyClientError`; callers
MUST treat it as DENY. There is no retry and no fallback to in-app logic.
``halt_status`` is the one exception: it never raises, an unknown state IS
"halted" (PM-F31).

Still marked ASSUMPTION (not defined by policy_client.base, which has no HTTP
transport yet; confirm against PolicyManager P3 ``ServicePolicyClient``):
the request bodies of ``approve``/``reject`` ({"freigebender": <id>}) and of
``consume`` (the decide request, as ``consume(approval_id, request)`` binds
the approval to the unchanged action).

Only the standard library is used (SOAR app packaging, PM-N01 spirit).
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol, Union

logger = logging.getLogger("soar_mcp.policy_client")


def approval_ref(freigabe_id: object) -> str:
    """Reference for an approval id in logs and error texts (PM-F42 / S14):
    a sha256 prefix, never the id itself. Identical to ``freigabe_hash`` in
    the Policy Manager audit and in ``pending_approvals``, so lines on both
    sides correlate. Empty id -> ``"-"``."""
    text = str(freigabe_id or "")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16] if text else "-"


_APPROVAL_IN_PATH = re.compile(r"(/v1/approvals/)([^/?#\s\"']+)")


def redact_path(text: str) -> str:
    """Replace approval ids in URL paths by ``#<approval_ref>`` (PM-F42)."""
    return _APPROVAL_IN_PATH.sub(
        lambda m: m.group(1) + "#" + approval_ref(urllib.parse.unquote(m.group(2))), text)

# Gate names exactly as the Policy Manager returns them (PM spec §5 example,
# identical to policy/policy_layer.py Gate names).
GATES: frozenset[str] = frozenset({"ALLOW", "APPROVE_1CLICK", "APPROVE_2PERSON", "DENY"})
APPROVAL_GATES: frozenset[str] = frozenset({"APPROVE_1CLICK", "APPROVE_2PERSON"})

# Codes (policy_client.base, PM §9). DENY decisions and failed operations.
CODE_NO_EVIDENCE = "NO_EVIDENCE"
CODE_INCOMPLETE_JUDGEMENT = "INCOMPLETE_JUDGEMENT"
CODE_HALTED = "HALTED"
CODE_INVALID_SEQUENCE = "INVALID_SEQUENCE"
CODE_UNAVAILABLE = "UNAVAILABLE"
CODE_INVALID_RESPONSE = "INVALID_RESPONSE"
CODE_NO_INITIATOR = "NO_INITIATOR"
# Approval lifecycle codes.
CODE_SELF_APPROVAL = "SELF_APPROVAL"
CODE_DUPLICATE = "DUPLICATE"
CODE_NO_APPROVER = "NO_APPROVER"
CODE_UNKNOWN_APPROVAL = "UNKNOWN_APPROVAL"
CODE_NOT_APPROVED = "NOT_APPROVED"
CODE_ACTION_CHANGED = "ACTION_CHANGED"
CODE_EXPIRED = "EXPIRED"
CODE_CONSUMED = "CONSUMED"

APPROVAL_STATES: frozenset[str] = frozenset({"pending", "approved", "rejected", "expired", "consumed"})

# freigabe_id / entscheidung_id travel inside URL paths: restrict the charset so
# a tampered id can never rewrite the path (PM example: "ap-5521", "pm-2026-10-17-000088").
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

_PATH_DECIDE = "/v1/decide"
_PATH_HALT = "/v1/halt"
_PATH_HEALTH = "/health"
_PATH_APPROVALS = "/v1/approvals/"


class PolicyClientError(Exception):
    """Transport or contract failure. Callers MUST treat it as DENY (fail-closed).

    ``kind`` is a short machine-readable class for audit lines:
    config | tls | timeout | unreachable | http | contract
    """

    def __init__(self, reason: str, kind: str = "error"):
        super().__init__(reason)
        self.reason = reason
        self.kind = kind

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.kind}: {self.reason}"


def _opt_int(value: Any) -> Optional[int]:
    try:
        return None if value is None or isinstance(value, bool) else int(value)
    except (TypeError, ValueError):
        return None


@dataclass(frozen=True)
class PolicyDecision:
    """One answer of POST /v1/decide (PM spec §5 example, ``Decision.to_wire``)."""

    entscheidung_id: str
    gate: str
    freigaben_noetig: int = 0
    freigabe_id: Optional[str] = None
    # Reason code of a DENY (policy_client.base ``Decision.code``: HALTED,
    # NO_EVIDENCE, INCOMPLETE_JUDGEMENT, NO_INITIATOR, UNAVAILABLE, ...).
    code: Optional[str] = None
    risiko_score: Optional[float] = None
    policy_version: str = ""
    begruendung: tuple = ()
    ablauf: str = ""
    raw: dict = field(default_factory=dict, compare=False, repr=False)

    @property
    def needs_approval(self) -> bool:
        return self.gate in APPROVAL_GATES

    @classmethod
    def from_response(cls, payload: object) -> "PolicyDecision":
        """Validate a decoded /v1/decide body. Anything that does not satisfy
        the contract raises PolicyClientError(kind="contract") — never a
        half-parsed decision that could read as ALLOW.

        A DENY may come without ``entscheidung_id`` (client-side denies in
        ``policy_client.base`` carry an empty id); every other gate must trace
        back to a decision (AN-06/AN-07, D22)."""
        if not isinstance(payload, dict):
            raise PolicyClientError("decide response is not a JSON object", "contract")
        gate = payload.get("gate")
        if not isinstance(gate, str) or gate.upper() not in GATES:
            raise PolicyClientError(f"decide response with unknown gate {gate!r}", "contract")
        gate = gate.upper()
        eid = payload.get("entscheidung_id")
        if eid is None:
            eid = ""
        if not isinstance(eid, str):
            raise PolicyClientError("decide response with non-string entscheidung_id", "contract")
        eid = eid.strip()
        if not eid and gate != "DENY":
            raise PolicyClientError(f"gate {gate} without entscheidung_id", "contract")
        freigabe_id = payload.get("freigabe_id")
        if freigabe_id in ("", None):
            freigabe_id = None
        elif not isinstance(freigabe_id, str) or not _ID_RE.match(freigabe_id):
            raise PolicyClientError("decide response with malformed freigabe_id", "contract")
        if gate in APPROVAL_GATES and not freigabe_id:
            # PM-F20: an approval gate MUST come with an approval process.
            raise PolicyClientError(f"gate {gate} without freigabe_id", "contract")
        needed = payload.get("freigaben_noetig")
        if needed is None:
            needed_val = 0
        else:
            needed_val = _opt_int(needed)
            if needed_val is None:
                raise PolicyClientError("decide response with non-integer freigaben_noetig", "contract")
        score = payload.get("risiko_score")
        try:
            score_val = float(score) if score is not None else None
        except (TypeError, ValueError):
            score_val = None
        code = payload.get("code")
        begr = payload.get("begruendung")
        return cls(
            entscheidung_id=eid,
            gate=gate,
            freigaben_noetig=needed_val,
            freigabe_id=freigabe_id,
            code=str(code) if isinstance(code, str) and code else None,
            risiko_score=score_val,
            policy_version=str(payload.get("policy_version") or ""),
            begruendung=tuple(begr) if isinstance(begr, list) else (),
            ablauf=str(payload.get("ablauf") or ""),
            raw=payload,
        )


@dataclass(frozen=True)
class ApprovalStatus:
    """State of an approval (``ApprovalStatus.to_wire``: freigabe_id, status,
    erteilt, noetig, code). An unknown status counts as ``expired``."""

    freigabe_id: str
    status: str
    erteilt: int = 0
    noetig: int = 0
    code: Optional[str] = None
    raw: dict = field(default_factory=dict, compare=False, repr=False)

    @property
    def approved(self) -> bool:
        return self.status == "approved"

    @property
    def pending(self) -> bool:
        return self.status == "pending"

    @classmethod
    def from_response(cls, payload: object, freigabe_id: str = "") -> "ApprovalStatus":
        if not isinstance(payload, dict):
            raise PolicyClientError("approval response is not a JSON object", "contract")
        status = payload.get("status")
        status = status if isinstance(status, str) and status in APPROVAL_STATES else "expired"
        code = payload.get("code")
        fid = payload.get("freigabe_id")
        return cls(
            freigabe_id=fid if isinstance(fid, str) and fid else freigabe_id,
            status=status,
            erteilt=_opt_int(payload.get("erteilt")) or 0,
            noetig=_opt_int(payload.get("noetig")) or 0,
            code=str(code) if isinstance(code, str) and code else None,
            raw=payload,
        )


@dataclass(frozen=True)
class ConsumeResult:
    """Outcome of consume (``ConsumeResult.to_wire``: gueltig, code).
    Only ``ok`` is True permits execution (PM-F23)."""

    ok: bool
    code: Optional[str] = None
    raw: dict = field(default_factory=dict, compare=False, repr=False)

    @classmethod
    def from_response(cls, payload: object) -> "ConsumeResult":
        if not isinstance(payload, dict) or payload.get("gueltig") is not True:
            code = payload.get("code") if isinstance(payload, dict) else None
            return cls(ok=False, code=str(code) if isinstance(code, str) and code else CODE_INVALID_RESPONSE,
                       raw=payload if isinstance(payload, dict) else {})
        code = payload.get("code")
        return cls(ok=True, code=str(code) if isinstance(code, str) and code else None, raw=payload)


@dataclass(frozen=True)
class HaltStatus:
    """Emergency stop state (``HaltStatus.to_wire``: angehalten, grund).
    Unknown state means halted (PM-F30/F31)."""

    halted: bool
    grund: str = ""

    @classmethod
    def from_response(cls, payload: object) -> "HaltStatus":
        if not isinstance(payload, dict) or payload.get("angehalten") is not False:
            grund = payload.get("grund") if isinstance(payload, dict) else None
            return cls(halted=True, grund=str(grund) if grund else "unknown halt state")
        return cls(halted=False, grund=str(payload.get("grund") or ""))


class PolicyClient(Protocol):
    """Interface shared by the HTTP client, the test stub and — later — the
    ``policy_client`` wheel from PolicyManager (AN-01: decide, approve,
    reject, approval_status, consume, halt_status)."""

    def decide(self, request: dict) -> PolicyDecision: ...

    def approve(self, freigabe_id: str, approver: str) -> ApprovalStatus: ...

    def reject(self, freigabe_id: str, approver: str) -> ApprovalStatus: ...

    def approval_status(self, freigabe_id: str) -> ApprovalStatus: ...

    def consume(self, freigabe_id: str, request: dict) -> ConsumeResult: ...

    def halt_status(self) -> HaltStatus: ...


def _check_id(value: object, what: str) -> str:
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise PolicyClientError(f"malformed {what}", "contract")
    return value


def _check_approver(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        # No accountable approver -> nothing is sent (PM-F21, OQ-7).
        raise PolicyClientError("approver identity missing", "contract")
    return value.strip()


class HttpPolicyClient:
    """Standard-library HTTPS client for the Policy Manager service (mode
    ``service``). mTLS material is given as file PATHS; the files are opened
    lazily on the first request and never logged."""

    def __init__(
        self,
        base_url: str,
        timeout_s: float,
        client_cert: str = "",
        client_key: str = "",
        ca: str = "",
        *,
        allow_insecure_http: bool = False,
    ):
        url = (base_url or "").strip().rstrip("/")
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme == "https" or (parsed.scheme == "http" and allow_insecure_http):
            pass
        else:
            # AN-02: the Policy Manager is reached over mTLS only. A plain http
            # URL is a configuration error, not a degraded mode.
            raise PolicyClientError("policy_service_url must use https://", "config")
        if not parsed.netloc:
            raise PolicyClientError("policy_service_url has no host", "config")
        if parsed.query or parsed.fragment:
            raise PolicyClientError("policy_service_url must not carry query/fragment", "config")
        self.base_url = url
        self.timeout_s = float(timeout_s) if timeout_s and float(timeout_s) > 0 else 5.0
        self.client_cert = client_cert or ""
        self.client_key = client_key or ""
        self.ca = ca or ""
        self._insecure = parsed.scheme == "http"
        self._ctx: Optional[ssl.SSLContext] = None

    # -- transport ---------------------------------------------------------

    def _ssl_context(self) -> Optional[ssl.SSLContext]:
        if self._insecure:
            return None
        if self._ctx is None:
            try:
                ctx = ssl.create_default_context(cafile=self.ca or None)
                if self.client_cert:
                    ctx.load_cert_chain(self.client_cert, self.client_key or None)
            except (ssl.SSLError, OSError, ValueError) as exc:
                # Paths are configuration, not secrets, so naming them is fine;
                # file contents are never read into a log.
                raise PolicyClientError(
                    f"mTLS material unusable ({type(exc).__name__})", "tls") from exc
            self._ctx = ctx
        return self._ctx

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body, default=str).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base_url + path, data=data, headers=headers, method=method)
        shown = f"{method} {redact_path(path)}"  # PM-F42: never the raw approval id
        ctx = self._ssl_context()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s, context=ctx) as resp:
                status = resp.status
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise PolicyClientError(f"{shown} -> HTTP {exc.code}", "http") from exc
        except (socket.timeout, TimeoutError) as exc:
            raise PolicyClientError(f"{shown} timed out after {self.timeout_s}s", "timeout") from exc
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, (socket.timeout, TimeoutError)):
                raise PolicyClientError(f"{shown} timed out after {self.timeout_s}s", "timeout") from exc
            if isinstance(reason, ssl.SSLError):
                raise PolicyClientError(f"{shown} TLS failure", "tls") from exc
            raise PolicyClientError(f"{shown} unreachable ({type(reason).__name__})", "unreachable") from exc
        except (ssl.SSLError, OSError) as exc:
            raise PolicyClientError(f"{shown} unreachable ({type(exc).__name__})", "unreachable") from exc
        if status != 200:
            raise PolicyClientError(f"{shown} -> HTTP {status}", "http")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise PolicyClientError(f"{shown} returned invalid JSON", "contract") from exc
        if not isinstance(payload, dict):
            raise PolicyClientError(f"{shown} returned a non-object body", "contract")
        return payload

    # -- PolicyClient ------------------------------------------------------

    def decide(self, request: dict) -> PolicyDecision:
        if not isinstance(request, dict):
            raise PolicyClientError("decide request must be a dict", "contract")
        payload = self._request("POST", _PATH_DECIDE, request)
        decision = PolicyDecision.from_response(payload)
        logger.info("[soar_mcp.policy_client] decide gate=%s entscheidung_id=%s freigabe_ref=%s code=%s",
                    decision.gate, decision.entscheidung_id or "-", approval_ref(decision.freigabe_id),
                    decision.code or "-")
        return decision

    def approve(self, freigabe_id: str, approver: str) -> ApprovalStatus:
        """One authenticated person approves (PM-F21). Self-approval and
        duplicates are judged by the Policy Manager (code in the status).
        ASSUMPTION: body {"freigebender": <approver>}."""
        fid = _check_id(freigabe_id, "freigabe_id")
        who = _check_approver(approver)
        payload = self._request("POST", _PATH_APPROVALS + fid + "/approve", {"freigebender": who})
        return ApprovalStatus.from_response(payload, fid)

    def reject(self, freigabe_id: str, approver: str) -> ApprovalStatus:
        fid = _check_id(freigabe_id, "freigabe_id")
        who = _check_approver(approver)
        payload = self._request("POST", _PATH_APPROVALS + fid + "/reject", {"freigebender": who})
        return ApprovalStatus.from_response(payload, fid)

    def approval_status(self, freigabe_id: str) -> ApprovalStatus:
        fid = _check_id(freigabe_id, "freigabe_id")
        return ApprovalStatus.from_response(self._request("GET", _PATH_APPROVALS + fid), fid)

    def consume(self, freigabe_id: str, request: dict) -> ConsumeResult:
        """Redeem an approval right before execution (PM-F23). The decide
        request travels along so the Policy Manager can verify the action is
        unchanged (ACTION_CHANGED otherwise). Only ``ok`` permits execution;
        transport failures raise (fail-closed)."""
        fid = _check_id(freigabe_id, "freigabe_id")
        if not isinstance(request, dict):
            raise PolicyClientError("consume request must be a dict", "contract")
        payload = self._request("POST", _PATH_APPROVALS + fid + "/consume", request)
        result = ConsumeResult.from_response(payload)
        logger.info("[soar_mcp.policy_client] consume freigabe_ref=%s ok=%s code=%s",
                    approval_ref(fid), result.ok, result.code or "-")
        return result

    def health(self) -> dict:
        """Operational probe (PM spec §5 lists GET /health; body unspecified).
        HTTP 200 with a JSON object means reachable; the body is returned
        as-is. Raises PolicyClientError otherwise."""
        return self._request("GET", _PATH_HEALTH)

    def halt_status(self) -> HaltStatus:
        """PM-F31: unknown state counts as halted, so every failure path
        returns ``halted=True`` instead of raising."""
        try:
            payload = self._request("GET", _PATH_HALT)
        except PolicyClientError as exc:
            logger.warning("[soar_mcp.policy_client] halt status unavailable (%s) -> treated as halted", exc)
            return HaltStatus(halted=True, grund=f"unavailable ({exc.kind})")
        status = HaltStatus.from_response(payload)
        if status.halted and "angehalten" not in payload:
            logger.warning("[soar_mcp.policy_client] halt status malformed -> treated as halted")
        return status


class StubPolicyClient:
    """In-memory Policy Manager for contract tests and local development.

    ``decision`` may be a PolicyDecision, a PolicyClientError (raised) or a
    callable(request) -> PolicyDecision. Every call is recorded in ``calls``
    as (method, argument) so tests can assert the adapter's behaviour.

    ``approvals`` maps freigabe_id -> {"status", "erteilt", "noetig",
    "initiator", "approvers"}; missing keys default to a pending approval
    needing one approver. The approval lifecycle mirrors
    ``policy_client.embedded`` (self-approval, duplicates, halt, single use).
    """

    def __init__(
        self,
        decision: Union[PolicyDecision, PolicyClientError, Callable[[dict], PolicyDecision], None] = None,
        *,
        halted: bool = False,
        consume_ok: bool = True,
        approvals: Optional[dict] = None,
        reachable: bool = True,
    ):
        self.decision = decision or PolicyDecision(entscheidung_id="stub-0001", gate="ALLOW")
        self.halted = halted
        self.reachable = reachable
        self.consume_ok = consume_ok
        self.approvals: dict = {}
        for fid, entry in (approvals or {}).items():
            self.add_approval(fid, **(entry or {}))
        self.calls: list[tuple[str, Any]] = []

    def add_approval(self, freigabe_id: str, status: str = "pending", erteilt: int = 0, noetig: int = 1,
                     initiator: str = "", approvers: Optional[list] = None, principal: str = "mensch") -> None:
        self.approvals[freigabe_id] = {
            "status": status, "erteilt": int(erteilt), "noetig": max(1, int(noetig)),
            "initiator": initiator, "approvers": list(approvers or []), "principal": principal,
        }

    def _status(self, fid: str, entry: dict, code: Optional[str] = None) -> ApprovalStatus:
        return ApprovalStatus(fid, entry["status"], erteilt=entry["erteilt"], noetig=entry["noetig"], code=code)

    def decide(self, request: dict) -> PolicyDecision:
        self.calls.append(("decide", request))
        d = self.decision
        if isinstance(d, PolicyClientError):
            raise d
        if callable(d) and not isinstance(d, PolicyDecision):
            return d(request)
        return d

    def _require(self, fid: str) -> dict:
        if not self.reachable:
            raise PolicyClientError("Policy Manager unreachable (stub)", "unreachable")
        entry = self.approvals.get(fid)
        if entry is None:
            raise PolicyClientError(f"GET {_PATH_APPROVALS}{fid} -> HTTP 404", "http")
        return entry

    def approve(self, freigabe_id: str, approver: str) -> ApprovalStatus:
        fid = _check_id(freigabe_id, "freigabe_id")
        who = _check_approver(approver)
        self.calls.append(("approve", (fid, who)))
        entry = self._require(fid)
        if entry["status"] != "pending":
            return self._status(fid, entry, CODE_NOT_APPROVED if entry["status"] != "approved" else None)
        if self.halted:
            return self._status(fid, entry, CODE_HALTED)
        if entry["initiator"] and who == entry["initiator"]:
            return self._status(fid, entry, CODE_SELF_APPROVAL)
        if who in entry["approvers"]:
            return self._status(fid, entry, CODE_DUPLICATE)
        entry["approvers"].append(who)
        entry["erteilt"] = len(entry["approvers"])
        if entry["erteilt"] >= entry["noetig"]:
            entry["status"] = "approved"
        return self._status(fid, entry)

    def reject(self, freigabe_id: str, approver: str) -> ApprovalStatus:
        fid = _check_id(freigabe_id, "freigabe_id")
        who = _check_approver(approver)
        self.calls.append(("reject", (fid, who)))
        entry = self._require(fid)
        if entry["status"] == "pending":
            entry["status"] = "rejected"
        return self._status(fid, entry)

    def approval_status(self, freigabe_id: str) -> ApprovalStatus:
        fid = _check_id(freigabe_id, "freigabe_id")
        self.calls.append(("approval_status", fid))
        return self._status(fid, self._require(fid))

    def consume(self, freigabe_id: str, request: dict) -> ConsumeResult:
        fid = _check_id(freigabe_id, "freigabe_id")
        self.calls.append(("consume", (fid, request)))
        if not self.reachable:
            raise PolicyClientError("Policy Manager unreachable (stub)", "unreachable")
        entry = self.approvals.get(fid)
        if entry is None:
            return ConsumeResult(False, CODE_UNKNOWN_APPROVAL)
        if not self.consume_ok:
            return ConsumeResult(False, CODE_EXPIRED)
        if entry["status"] == "consumed":
            return ConsumeResult(False, CODE_CONSUMED)
        if entry["status"] != "approved":
            return ConsumeResult(False, CODE_NOT_APPROVED)
        if entry.get("principal") == "agent" and self.halted:
            entry["status"] = "expired"
            return ConsumeResult(False, CODE_HALTED)
        entry["status"] = "consumed"
        return ConsumeResult(True)

    def health(self) -> dict:
        self.calls.append(("health", None))
        if not self.reachable:
            raise PolicyClientError("GET /health unreachable (stub)", "unreachable")
        return {"status": "ok"}

    def halt_status(self) -> HaltStatus:
        self.calls.append(("halt_status", None))
        if not self.reachable:
            return HaltStatus(halted=True, grund="unavailable (stub)")  # PM-F31: unknown -> halted
        return HaltStatus(halted=self.halted, grund="stub halt" if self.halted else "")


def build_policy_client(config: object) -> Optional[PolicyClient]:
    """Return the client for the configured mode, or None when no external
    decision is wanted (legacy path) or possible (invalid mode).

    The caller decides what None means: legacy -> today's in-app gate,
    invalid -> refuse every write tool (MCP-G03). This function never raises
    for a *missing* service; a malformed URL raises PolicyClientError(config)
    which the adapter turns into DENY.
    """
    from soar_mcp_config import POLICY_MODE_SERVICE, policy_effective_mode  # lazy: keep policy/ standalone

    if policy_effective_mode(config) != POLICY_MODE_SERVICE:
        return None
    return HttpPolicyClient(
        getattr(config, "policy_service_url", ""),
        getattr(config, "policy_timeout_s", 5.0),
        getattr(config, "policy_client_cert", ""),
        getattr(config, "policy_client_key", ""),
        getattr(config, "policy_ca", ""),
    )
