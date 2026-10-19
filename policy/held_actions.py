"""Held actions for Policy Manager mode ``service`` (SPEC-MCP Phase 3.2, MCP-W06,
concept OQ-16).

When the Policy Manager answers APPROVE_1CLICK / APPROVE_2PERSON the action is
held. The Policy Manager keeps the approval process and a binding of the
action (consume answers ACTION_CHANGED for anything else) but not the tool
arguments, so the app remembers them here under the ``freigabe_id``:
``approve_action`` (3.4) and the re-call with ``freigabe_id`` (3.3) redeem the
approval via ``consume`` and execute exactly what was held.

Modeled on policy/approvals.py: file-backed so it survives SOAR's
multi-process REST handler, fcntl-locked around read-modify-write, mode 0600,
pruned on every access. Entries expire with the decision's ``ablauf``
(fallback: 10 minutes). Never stored: approval_token, confirm_token,
freigabe_id arguments, token values, mTLS material.
"""
from __future__ import annotations

import contextlib
import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

_TTL_DEFAULT = 600.0  # seconds, when the decision carries no usable ablauf

# Arguments that belong to gates, never to the held action (same set as service_gate).
_GATE_ARGS: frozenset[str] = frozenset({"agent_context", "approval_token", "confirm_token", "freigabe_id"})


def expiry_from_ablauf(ablauf: str, now: Optional[float] = None) -> float:
    """Unix time at which a held action expires. ``ablauf`` is ISO 8601 (PM
    example: 2026-10-17T09:20:00+02:00); naive timestamps count as UTC;
    unparsable -> now + 10 min."""
    now = time.time() if now is None else now
    text = (ablauf or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return now + _TTL_DEFAULT
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


@dataclass(frozen=True)
class HeldAction:
    freigabe_id: str
    tool: str
    args: dict
    request: dict                 # the decide request, re-sent on consume (ACTION_CHANGED guard)
    entscheidung_id: str = ""
    gate: str = ""
    noetig: int = 1
    initiator: str = ""           # principal_identity() of the requester
    principal_type: str = "mensch"
    expires_at: float = 0.0
    created_at: float = field(default_factory=time.time)

    @classmethod
    def build(cls, freigabe_id: str, tool: str, args: dict, request: dict, *, entscheidung_id: str = "",
              gate: str = "", noetig: int = 1, initiator: str = "", principal_type: str = "mensch",
              ablauf: str = "") -> "HeldAction":
        clean = {k: v for k, v in (args or {}).items() if k not in _GATE_ARGS}
        return cls(freigabe_id=freigabe_id, tool=tool, args=clean, request=dict(request or {}),
                   entscheidung_id=entscheidung_id or "", gate=gate or "", noetig=max(1, int(noetig or 1)),
                   initiator=initiator or "", principal_type=principal_type or "mensch",
                   expires_at=expiry_from_ablauf(ablauf))

    @property
    def expired(self) -> bool:
        return self.expires_at <= time.time()

    @classmethod
    def from_entry(cls, data: Any) -> Optional["HeldAction"]:
        if not isinstance(data, dict):
            return None
        try:
            return cls(
                freigabe_id=str(data["freigabe_id"]), tool=str(data["tool"]),
                args=dict(data.get("args") or {}), request=dict(data.get("request") or {}),
                entscheidung_id=str(data.get("entscheidung_id") or ""), gate=str(data.get("gate") or ""),
                noetig=max(1, int(data.get("noetig") or 1)), initiator=str(data.get("initiator") or ""),
                principal_type=str(data.get("principal_type") or "mensch"),
                expires_at=float(data.get("expires_at") or 0.0), created_at=float(data.get("created_at") or 0.0),
            )
        except (KeyError, TypeError, ValueError):
            return None


class HeldActionStore:
    """File-backed held actions keyed on freigabe_id."""

    def __init__(self, path: Optional[str] = None) -> None:
        app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self._path = path or os.path.join(app_dir, "local", "held_actions.json")
        self._lock = threading.Lock()

    # --- persistence (mirrors ApprovalStore) --------------------------------

    def _load(self) -> dict:
        try:
            if os.path.exists(self._path):
                with open(self._path, encoding="utf-8") as fh:
                    data = json.load(fh)
                    return data if isinstance(data, dict) else {}
        except Exception:
            pass
        return {}

    def _save(self, data: dict) -> None:
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, default=str)
        os.replace(tmp, self._path)
        try:
            os.chmod(self._path, 0o600)
        except Exception:
            pass

    @staticmethod
    def _prune(data: dict) -> dict:
        now = time.time()
        out = {}
        for k, v in data.items():
            if isinstance(v, dict):
                try:
                    if float(v.get("expires_at") or 0.0) > now:
                        out[k] = v
                except (TypeError, ValueError):
                    continue
        return out

    @contextlib.contextmanager
    def _file_lock(self):
        try:
            import fcntl
        except Exception:
            yield
            return
        fd = None
        try:
            os.makedirs(os.path.dirname(self._path), exist_ok=True)
            fd = open(self._path + ".lock", "w", encoding="utf-8")
            fcntl.flock(fd.fileno(), fcntl.LOCK_EX)
        except Exception:
            if fd is not None:
                fd.close()
            fd = None
        try:
            yield
        finally:
            if fd is not None:
                try:
                    fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
                except Exception:
                    pass
                fd.close()

    # --- API -----------------------------------------------------------------

    def put(self, action: HeldAction) -> None:
        """Remember a held action (overwrites an entry with the same freigabe_id).
        Raises on I/O failure; the caller decides how to report it."""
        with self._lock, self._file_lock():
            data = self._prune(self._load())
            data[action.freigabe_id] = asdict(action)
            self._save(data)

    def get(self, freigabe_id: str) -> Optional[HeldAction]:
        """The held action, or None when unknown or expired."""
        with self._lock, self._file_lock():
            data = self._prune(self._load())
            return HeldAction.from_entry(data.get(str(freigabe_id)))

    def remove(self, freigabe_id: str) -> None:
        with self._lock, self._file_lock():
            data = self._prune(self._load())
            if str(freigabe_id) in data:
                del data[str(freigabe_id)]
                self._save(data)

    def count(self) -> int:
        with self._lock, self._file_lock():
            return len(self._prune(self._load()))
