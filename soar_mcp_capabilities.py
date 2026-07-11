"""
SOAR MCP Server — Capability Detection Layer (issue #68, part 1)

Runtime detection of how *this* SOAR instance actually behaves, instead of
version-only assumptions. Verified against SOAR 8.5.0.248, where:
  - /coa/playbooks/{id} returns an extractable node/edge graph (live),
  - the export archive is available as a fallback,
  - the REST playbook record carries a Python payload ("rest_python"),
  - there is NO /rest/playbook/{id}/validate endpoint (passed_validation flag),
  - pylint is available server-side.

This module only *detects and reports* capabilities (read-only probes). Rewiring
the internal COA consumers (_get_coa_nodes_edges / _select_playbook_python /
_resolve_current_id) to consume the report is a deliberate, separately-tested
follow-up so the freshly-restabilised COA paths are not destabilised.

Copyright 2026 Andreas Buis
"""
from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Optional


@dataclass
class CapabilityReport:
    """Observed capabilities of a SOAR instance's playbook/COA surface."""
    coa_endpoint_available: bool = False
    coa_graph_extractable: bool = False
    export_fallback_available: bool = False
    python_source: str = "none"          # rest_python | coa_python | export_archive | coa_usercode | none
    validation_method: str = "unknown"   # passed_validation_flag | validate_endpoint | none
    node_count: Optional[int] = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _coa_data_has_nodes(coa_data: Any) -> tuple[bool, Optional[int]]:
    """Best-effort: does a COA payload expose an extractable node collection?
    Mirrors the shapes _get_coa_nodes_edges handles (A–D), without importing it
    (keeps this module dependency-light and safe to unit-test in isolation)."""
    if not isinstance(coa_data, dict):
        return False, None
    coa_sub = coa_data.get("coa") or {}
    data_sub = coa_sub.get("data") or coa_data.get("data") or {}
    cd = coa_data.get("coa_data")
    if isinstance(cd, dict):
        data_sub = data_sub or cd
    nodes = (
        (data_sub.get("nodes") if isinstance(data_sub, dict) else None)
        or (cd.get("nodes") if isinstance(cd, dict) else None)
        or coa_data.get("nodes")
    )
    if isinstance(nodes, dict):
        return (len(nodes) > 0), len(nodes)
    if isinstance(nodes, list):
        return (len(nodes) > 0), len(nodes)
    # No explicit node collection, but a count field still signals a live graph.
    nc = coa_data.get("node_count")
    if isinstance(nc, int):
        return (nc > 0), nc
    return False, None


def detect_capabilities(client, sample_playbook_id: int) -> CapabilityReport:
    """Probe a known-good playbook id with safe, read-only calls and report what
    this SOAR instance actually supports. Never raises — degrades to a report
    with notes on any probe failure."""
    report = CapabilityReport()

    # 1. COA endpoint + graph extractability.
    coa_data, coa_err = client._coa_get(f"playbooks/{sample_playbook_id}")
    if coa_err:
        report.notes.append(f"coa_probe_failed: {coa_err}")
    else:
        report.coa_endpoint_available = True
        has_nodes, nc = _coa_data_has_nodes(coa_data)
        report.coa_graph_extractable = has_nodes
        report.node_count = nc
        if not has_nodes:
            report.notes.append("coa_endpoint_available_but_nodes_not_extractable")

    # 2. Python source (prefer REST record; else export archive availability).
    rest_data, rest_err = client.get(f"playbook/{sample_playbook_id}")
    if isinstance(rest_data, dict) and any(
        isinstance(rest_data.get(k), str) and rest_data.get(k).strip()
        for k in ("python", "code", "script", "playbook_run_data")
    ):
        report.python_source = "rest_python"
        report.validation_method = (
            "passed_validation_flag" if "passed_validation" in rest_data else "unknown"
        )
    elif rest_err:
        report.notes.append(f"rest_probe_failed: {rest_err}")

    # 3. Export fallback availability (binary archive).
    content, exp_err = client.get_binary(f"playbook/{sample_playbook_id}/export")
    if content:
        report.export_fallback_available = True
        if report.python_source == "none":
            report.python_source = "export_archive"
    elif exp_err:
        report.notes.append(f"export_probe_failed: {exp_err}")

    if report.validation_method == "unknown" and report.coa_endpoint_available:
        # SOAR 8.5 has no /validate endpoint; passed_validation is the signal.
        report.validation_method = "passed_validation_flag"

    return report


# ── Per-process cached accessor (issue #68 part 2) ────────────────────────────
# Detection issues 3 read-only probes; caching avoids re-probing on every COA
# tool call within a short window. Per-process only (like the rate limiter).

_cache: dict[str, tuple[CapabilityReport, float]] = {}
_cache_lock = threading.Lock()


def get_capabilities(client, sample_playbook_id: int, *, ttl: float = 300.0) -> CapabilityReport:
    """Cached capability detection, keyed on the client base URL + sample id."""
    key = f"{getattr(client, '_base_url', '')}|{sample_playbook_id}"
    now = time.time()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and hit[1] > now:
            return hit[0]
    report = detect_capabilities(client, sample_playbook_id)
    with _cache_lock:
        _cache[key] = (report, now + ttl)
    return report


def explain_empty_graph(client, playbook_id: int) -> Optional[dict]:
    """When a tool gets an empty node/edge graph, return a capability-based
    finding explaining WHY (instead of a silent 0), or None if a graph is
    actually available (so the emptiness is genuine, not a capability gap)."""
    caps = get_capabilities(client, playbook_id)
    if caps.coa_graph_extractable or caps.export_fallback_available:
        return None
    if not caps.coa_endpoint_available:
        msg = ("COA endpoint is unreachable and no export fallback is available — "
               "the graph could not be retrieved (not necessarily empty).")
    else:
        msg = ("COA endpoint responded but no extractable node graph was found and "
               "the export fallback is unavailable — graph could not be retrieved.")
    return {"severity": "warn", "code": "graph_unavailable",
            "source": "capabilities", "message": msg}
