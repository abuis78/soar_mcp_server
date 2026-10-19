"""Policy Manager client for soar_mcp_server (SPEC-MCP MCP-G02 / MCP-G04,
Anbindung AN-01 / AN-02 / AN-04, SPEC-MCP Phase 2.2).

This module is the transport layer only. It knows nothing about tools, cases
or gates' meaning; the adapter (``_policy_gate``) builds the request and
translates the decision into the user-facing messages.

Contract (PolicyManager spec §5, *draft*):

    POST /v1/decide                      -> PolicyDecision
    GET  /v1/approvals/{freigabe_id}     -> dict (status of an approval)
    POST /v1/approvals/{freigabe_id}/consume -> dict (redeem before execution)
    GET  /v1/halt                        -> halted? (fail-safe: unknown = halted)

Fail-closed by design (AN-04, PM §9 "Policy Manager nicht erreichbar"):
every transport or contract failure raises :class:`PolicyClientError`; callers
MUST treat it as DENY. There is no retry and no fallback to in-app logic.

Assumptions marked ``ASSUMPTION`` are not covered by the spec example and
must be confirmed against the real service (PolicyManager P3); the stub and
the tests encode them so a mismatch shows up as a failing contract test.

Only the standard library is used (SOAR app packaging, PM-N01 spirit).
"""

from __future__ import annotations

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

# Gate names exactly as the Policy Manager returns them (PM spec §5 example,
# identical to policy/policy_layer.py Gate names).
GATES: frozenset[str] = frozenset({"ALLOW", "APPROVE_1CLICK", "APPROVE_2PERSON", "DENY"})
APPROVAL_GATES: frozenset[str] = frozenset({"APPROVE_1CLICK", "APPROVE_2PERSON"})

# freigabe_id / entscheidung_id travel inside URL paths: restrict the charset so
# a tampered id can never rewrite the path (PM example: "ap-5521", "pm-2026-10-17-000088").
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

_PATH_DECIDE = "/v1/decide"
_PATH_HALT = "/v1/halt"
_PATH_APPROVALS = "/v1/approvals/"


class PolicyClientError(Exception):
    """Transport or contract failure. Callers MUST treat it as DENY (fail-closed).

    ``kind`` is a short machine-readable class for audit lines:
    config | tls | timeout | unreachable | http | contract | halted
    """

    def __init__(self, reason: str, kind: str = "error"):
        super().__init__(reason)
        self.reason = reason
        self.kind = kind

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.kind}: {self.reason}"


@dataclass(frozen=True)
class PolicyDecision:
    """One answer of POST /v1/decide (PM spec §5 example). Field names are the
    wire names on purpose (Runtime concept E7: wire = spec names)."""

    entscheidung_id: str
    gate: str
    freigaben_noetig: int = 0
    freigabe_id: Optional[str] = None
    # ASSUMPTION: the reason code of a DENY (HALTED, NO_EVIDENCE,
    # INCOMPLETE_JUDGEMENT, PM spec §9) is carried in a top-level "code" field.
    # The spec example shows no such field; confirm against PolicyManager P3.
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
        half-parsed decision that could read as ALLOW."""
        if not isinstance(payload, dict):
            raise PolicyClientError("decide response is not a JSON object", "contract")
        eid = payload.get("entscheidung_id")
        if not isinstance(eid, str) or not eid.strip():
            raise PolicyClientError("decide response without entscheidung_id", "contract")
        gate = payload.get("gate")
        if not isinstance(gate, str) or gate.upper() not in GATES:
            raise PolicyClientError(f"decide response with unknown gate {gate!r}", "contract")
        gate = gate.upper()
        freigabe_id = payload.get("freigabe_id")
        if freigabe_id is not None and (not isinstance(freigabe_id, str) or not _ID_RE.match(freigabe_id)):
            raise PolicyClientError("decide response with malformed freigabe_id", "contract")
        if gate in APPROVAL_GATES and not freigabe_id:
            # PM-F20: an approval gate MUST come with an approval process.
            raise PolicyClientError(f"gate {gate} without freigabe_id", "contract")
        try:
            needed = int(payload.get("freigaben_noetig") or 0)
        except (TypeError, ValueError):
            raise PolicyClientError("decide response with non-integer freigaben_noetig", "contract")
        score = payload.get("risiko_score")
        try:
            score_val = float(score) if score is not None else None
        except (TypeError, ValueError):
            score_val = None
        code = payload.get("code")
        begr = payload.get("begruendung")
        return cls(
            entscheidung_id=eid.strip(),
            gate=gate,
            freigaben_noetig=needed,
            freigabe_id=freigabe_id,
            code=str(code) if isinstance(code, str) and code else None,
            risiko_score=score_val,
            policy_version=str(payload.get("policy_version") or ""),
            begruendung=tuple(begr) if isinstance(begr, list) else (),
            ablauf=str(payload.get("ablauf") or ""),
            raw=payload,
        )


class PolicyClient(Protocol):
    """Interface shared by the HTTP client, the test stub and — later — the
    ``policy_client`` wheel from PolicyManager P1 (AN-01: decide,
    approval_status, consume, halt_status)."""

    def decide(self, request: dict) -> PolicyDecision: ...

    def approval_status(self, freigabe_id: str) -> dict: ...

    def consume(self, freigabe_id: str) -> dict: ...

    def halt_status(self) -> bool: ...


def _check_id(value: object, what: str) -> str:
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise PolicyClientError(f"malformed {what}", "contract")
    return value


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
        ctx = self._ssl_context()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s, context=ctx) as resp:
                status = resp.status
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise PolicyClientError(f"{method} {path} -> HTTP {exc.code}", "http") from exc
        except (socket.timeout, TimeoutError) as exc:
            raise PolicyClientError(f"{method} {path} timed out after {self.timeout_s}s", "timeout") from exc
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, (socket.timeout, TimeoutError)):
                raise PolicyClientError(f"{method} {path} timed out after {self.timeout_s}s", "timeout") from exc
            if isinstance(reason, ssl.SSLError):
                raise PolicyClientError(f"{method} {path} TLS failure", "tls") from exc
            raise PolicyClientError(f"{method} {path} unreachable ({type(reason).__name__})", "unreachable") from exc
        except (ssl.SSLError, OSError) as exc:
            raise PolicyClientError(f"{method} {path} unreachable ({type(exc).__name__})", "unreachable") from exc
        if status != 200:
            raise PolicyClientError(f"{method} {path} -> HTTP {status}", "http")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise PolicyClientError(f"{method} {path} returned invalid JSON", "contract") from exc
        if not isinstance(payload, dict):
            raise PolicyClientError(f"{method} {path} returned a non-object body", "contract")
        return payload

    # -- PolicyClient ------------------------------------------------------

    def decide(self, request: dict) -> PolicyDecision:
        if not isinstance(request, dict):
            raise PolicyClientError("decide request must be a dict", "contract")
        payload = self._request("POST", _PATH_DECIDE, request)
        decision = PolicyDecision.from_response(payload)
        logger.info("[soar_mcp.policy_client] decide gate=%s entscheidung_id=%s freigabe_id=%s code=%s",
                    decision.gate, decision.entscheidung_id, decision.freigabe_id or "-",
                    decision.code or "-")
        return decision

    def approval_status(self, freigabe_id: str) -> dict:
        fid = _check_id(freigabe_id, "freigabe_id")
        return self._request("GET", _PATH_APPROVALS + fid)

    def consume(self, freigabe_id: str) -> dict:
        """Redeem an approval right before execution (PM-F23). Success = HTTP 200
        with a JSON object; everything else raises (expired, used, changed,
        unreachable) and the caller must not execute."""
        fid = _check_id(freigabe_id, "freigabe_id")
        return self._request("POST", _PATH_APPROVALS + fid + "/consume", {})

    def halt_status(self) -> bool:
        """True = halted. PM-F31: unknown state counts as halted, so every
        failure path returns True instead of raising."""
        try:
            payload = self._request("GET", _PATH_HALT)
        except PolicyClientError as exc:
            logger.warning("[soar_mcp.policy_client] halt status unavailable (%s) -> treated as halted", exc)
            return True
        # ASSUMPTION: GET /v1/halt answers {"halted": bool}. Missing or
        # non-boolean -> halted (fail-safe).
        halted = payload.get("halted")
        if not isinstance(halted, bool):
            logger.warning("[soar_mcp.policy_client] halt status malformed -> treated as halted")
            return True
        return halted


class StubPolicyClient:
    """In-memory Policy Manager for contract tests and local development.

    ``decision`` may be a PolicyDecision, a PolicyClientError (raised) or a
    callable(request) -> PolicyDecision. Every call is recorded in ``calls``
    as (method, argument) so tests can assert the adapter's behaviour.
    """

    def __init__(
        self,
        decision: Union[PolicyDecision, PolicyClientError, Callable[[dict], PolicyDecision], None] = None,
        *,
        halted: bool = False,
        consume_ok: bool = True,
        approvals: Optional[dict] = None,
    ):
        self.decision = decision or PolicyDecision(entscheidung_id="stub-0001", gate="ALLOW")
        self.halted = halted
        self.consume_ok = consume_ok
        self.approvals: dict = dict(approvals or {})
        self.calls: list[tuple[str, Any]] = []

    def decide(self, request: dict) -> PolicyDecision:
        self.calls.append(("decide", request))
        d = self.decision
        if isinstance(d, PolicyClientError):
            raise d
        if callable(d) and not isinstance(d, PolicyDecision):
            return d(request)
        return d

    def approval_status(self, freigabe_id: str) -> dict:
        fid = _check_id(freigabe_id, "freigabe_id")
        self.calls.append(("approval_status", fid))
        if fid not in self.approvals:
            raise PolicyClientError(f"GET {_PATH_APPROVALS}{fid} -> HTTP 404", "http")
        return dict(self.approvals[fid])

    def consume(self, freigabe_id: str) -> dict:
        fid = _check_id(freigabe_id, "freigabe_id")
        self.calls.append(("consume", fid))
        if not self.consume_ok:
            raise PolicyClientError(f"POST {_PATH_APPROVALS}{fid}/consume -> HTTP 409", "http")
        self.approvals.pop(fid, None)
        return {"freigabe_id": fid, "consumed": True}

    def halt_status(self) -> bool:
        self.calls.append(("halt_status", None))
        return self.halted


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
