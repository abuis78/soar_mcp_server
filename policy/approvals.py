"""Approval store for the policy layer (issue #138, Phase 3).

Collects one (APPROVE_1CLICK) or two *distinct* (APPROVE_2PERSON) human
approvals for a held run_playbook before it may execute. Modeled on the #50
_ConfirmStore: file-backed so it survives SOAR's multi-process REST handler,
fcntl-locked around the read-modify-write, TTL-bound, single-use on completion.

Identity is the scoped-token soar_user_id (D3). Two-person separation is
enforced here: the same approver id cannot count twice, so two *different*
humans (two different scoped tokens) are required — no self-approval.

Fail-safe: a missing/expired/mismatched token yields INVALID; nothing executes
without the full set of distinct approvers. Only a SHA-256 hash of the token is
ever stored, never the raw token.

An entry is a 5-list: [tool, args_hash, expiry, needed, [approver_ids...]].
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Optional

_TTL_DEFAULT = 600.0  # 10 min — two humans need longer to coordinate than a confirm


@dataclass(frozen=True)
class ApprovalResult:
    """Outcome of submit(). status is one of: approved | pending | duplicate | invalid."""
    status: str
    have: int = 0
    need: int = 0

    @property
    def approved(self) -> bool:
        return self.status == "approved"


class ApprovalStore:
    """File-backed, TTL-bound, distinct-approver approval tokens keyed on (tool, args)."""

    def __init__(self, path: Optional[str] = None) -> None:
        app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self._path = path or os.path.join(app_dir, "local", "pending_approvals.json")
        self._lock = threading.Lock()

    # --- hashing (raw token / args never stored in the clear) ----------------

    @staticmethod
    def _args_hash(tool: str, args: dict) -> str:
        blob = tool + "|" + json.dumps(args, sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()

    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    # --- persistence ---------------------------------------------------------

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
        try:
            os.makedirs(os.path.dirname(self._path), exist_ok=True)
            tmp = self._path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(data, fh)
            os.replace(tmp, self._path)
            try:
                os.chmod(self._path, 0o600)
            except Exception:
                pass
        except Exception:
            pass

    @staticmethod
    def _prune(data: dict) -> dict:
        now = time.time()
        return {k: v for k, v in data.items()
                if isinstance(v, list) and len(v) == 5 and v[2] > now}

    @contextlib.contextmanager
    def _file_lock(self):
        """Exclusive cross-process lock around read-modify-write (mirrors #127)."""
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

    def issue(self, tool: str, args: dict, needed: int, ttl: float = _TTL_DEFAULT) -> str:
        """Open an approval request; return the token the approver(s) must present."""
        needed = max(1, int(needed))
        token = "approve_" + secrets.token_urlsafe(9)
        with self._lock, self._file_lock():
            data = self._prune(self._load())
            data[self._token_hash(token)] = [
                tool, self._args_hash(tool, args), time.time() + ttl, needed, []
            ]
            self._save(data)
        return token

    def submit(self, token: str, tool: str, args: dict, approver_id: str) -> ApprovalResult:
        """Record one approval from approver_id. Returns the resulting state.

        - approved : the needed number of *distinct* approvers is met (token consumed)
        - pending  : recorded, more distinct approver(s) still required
        - duplicate: approver_id already approved this token (not counted again)
        - invalid  : no/expired/mismatched token, or empty approver_id
        """
        approver = (approver_id or "").strip()
        if not approver:
            return ApprovalResult("invalid")
        th = self._token_hash(str(token))
        now = time.time()
        with self._lock, self._file_lock():
            data = self._load()
            entry = data.get(th)
            if entry is None or not isinstance(entry, list) or len(entry) != 5 or entry[2] <= now:
                if entry is not None:
                    data.pop(th, None)     # expired/garbage cleanup
                    self._save(data)
                return ApprovalResult("invalid")
            # Wrong tool/args must NOT nuke a legitimate pending approval.
            if entry[0] != tool or entry[1] != self._args_hash(tool, args):
                return ApprovalResult("invalid")

            needed = int(entry[3])
            approvers = list(entry[4]) if isinstance(entry[4], list) else []
            if approver in approvers:
                return ApprovalResult("duplicate", have=len(approvers), need=needed)

            approvers.append(approver)
            if len(approvers) >= needed:
                data.pop(th, None)         # single-use: consume on completion
                self._save(data)
                return ApprovalResult("approved", have=len(approvers), need=needed)

            entry[4] = approvers
            data[th] = entry
            self._save(data)
            return ApprovalResult("pending", have=len(approvers), need=needed)
