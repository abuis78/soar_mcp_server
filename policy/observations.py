"""Hit counts observed by this server for D22 (PolicyManager issue #16, variant A, M1).

The Policy Manager rule ``beleg_inhalt`` (PM 0.6.0) needs, for agent requests,
``kontext.belege = [{beleg_id, treffer}]``. ``treffer`` must be an observation,
never a number the caller (a model) reports. This server can only observe its
own SOAR reads, so it records them here:

* A read tool that knows its result size reports it via ``note_hits(n)``
  (``list_cases`` / ``search_cases`` / ``list_artifacts`` / ``list_case_notes``:
  number of rows returned; ``get_case`` / ``get_artifact``: 1 for a record).
  Tools that do not call it have no count; errors never count.
* The handler stores the count for broker reads under the Tool Broker's
  ``broker_aufruf_id`` (the id an agent later cites in ``beleg_ids``),
  together with the broker's ``agent_id`` when given.
* ``service_gate.build_decide_request`` looks every ``beleg_id`` up. Unknown,
  expired, or bound to another agent -> ``treffer = None`` (PM: no hit).

Stored per entry: count, tool name, agent_id, timestamps. Never stored: tool
arguments, results, token values. File-backed (SOAR runs several handler
processes), fcntl-locked, mode 0600, pruned on every access. Every SOAR install
wipes ``local/``; that only drops observations, which is fail-closed.
"""
from __future__ import annotations

import contextlib
import contextvars
import json
import os
import threading
import time
from typing import Optional

TTL_SECONDS = 6 * 3600.0     # an agent run cites evidence from the same run
MAX_ENTRIES = 5000           # bound the file; oldest entries go first
MAX_ID_LEN = 128

_hits: contextvars.ContextVar[Optional[int]] = contextvars.ContextVar("soar_mcp_observed_hits",
                                                                       default=None)


def reset_hits() -> None:
    """Called by the handler before a tool runs."""
    _hits.set(None)


def note_hits(count: int) -> None:
    """A read tool reports how many rows it returned (>= 0)."""
    if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
        _hits.set(count)


def take_hits() -> Optional[int]:
    """The count noted by the tool that just ran, or None; clears it."""
    value = _hits.get()
    _hits.set(None)
    return value


class ObservationStore:
    """File-backed hit counts keyed on the Tool Broker's aufruf_id."""

    def __init__(self, path: Optional[str] = None) -> None:
        app_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self._path = path or os.path.join(app_dir, "local", "observations.json")
        self._lock = threading.Lock()

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
            json.dump(data, fh)
        os.replace(tmp, self._path)
        try:
            os.chmod(self._path, 0o600)
        except Exception:
            pass

    @staticmethod
    def _prune(data: dict, now: float) -> dict:
        out = {}
        for k, v in data.items():
            try:
                if isinstance(v, dict) and float(v.get("expires_at") or 0.0) > now:
                    out[k] = v
            except (TypeError, ValueError):
                continue
        if len(out) > MAX_ENTRIES:
            keep = sorted(out.items(), key=lambda kv: float(kv[1].get("observed_at") or 0.0))
            out = dict(keep[-MAX_ENTRIES:])
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

    def record(self, aufruf_id: str, treffer: int, *, tool: str = "", agent_id: str = "") -> None:
        """Remember the hit count of one broker read. Raises on I/O failure."""
        key = str(aufruf_id or "").strip()
        if not key or len(key) > MAX_ID_LEN:
            return
        if isinstance(treffer, bool) or not isinstance(treffer, int) or treffer < 0:
            return
        now = time.time()
        with self._lock, self._file_lock():
            data = self._prune(self._load(), now)
            data[key] = {"treffer": treffer, "tool": str(tool or "")[:64],
                         "agent_id": str(agent_id or "").strip()[:MAX_ID_LEN],
                         "observed_at": now, "expires_at": now + TTL_SECONDS}
            self._save(data)

    def treffer_for(self, beleg_id: str, agent_id: str = "") -> Optional[int]:
        """The observed count for ``beleg_id``, or None (unknown, expired, or
        observed for a different agent). Never raises."""
        try:
            with self._lock, self._file_lock():
                entry = self._prune(self._load(), time.time()).get(str(beleg_id or "").strip())
        except Exception:
            return None
        if not isinstance(entry, dict):
            return None
        bound = str(entry.get("agent_id") or "")
        if bound and bound != str(agent_id or ""):
            return None
        t = entry.get("treffer")
        return t if isinstance(t, int) and not isinstance(t, bool) and t >= 0 else None


_store: Optional[ObservationStore] = None
_store_override: Optional[ObservationStore] = None


def set_observation_store_override(store: Optional[ObservationStore]) -> None:
    """Tests: use this store (e.g. in a temp dir) instead of local/observations.json."""
    global _store_override
    _store_override = store


def get_observation_store() -> ObservationStore:
    global _store
    if _store_override is not None:
        return _store_override
    if _store is None:
        _store = ObservationStore()
    return _store
