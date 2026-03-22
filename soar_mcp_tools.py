"""
SOAR MCP Server — Tool Definitions and Implementations

Each function here corresponds to one MCP tool that an AI client (Claude, etc.)
can invoke. All tools call the Splunk SOAR REST API using the auth token supplied
by the MCP client in the request headers.

Design principles:
  - Read-only tools are safe and enabled by default.
  - Write tools (add_case_note, run_playbook, etc.) are disabled by default.
  - All responses are human-readable text blocks (MCP content type "text").
  - Errors are returned as structured error text, not raised exceptions.
  - No tool modifies SOAR state unless explicitly enabled in mcp.conf.

SOAR REST API base: https://<soar>/rest/
Auth header:        ph-auth-token: <token>

Copyright 2026 Andreas Buis
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

import requests

from soar_mcp_config import McpServerConfig

logger = logging.getLogger(__name__)

# ── SOAR severity ordering (for min_severity filtering) ───────────────────────
_SEVERITY_ORDER = {"high": 4, "medium": 3, "low": 2, "informational": 1, "": 0}

# ── SOAR status labels ─────────────────────────────────────────────────────────
_VALID_STATUSES = {"open", "closed", "resolved", "new", "in_progress"}
_VALID_SEVERITIES = {"high", "medium", "low", "informational"}


# ==============================================================================
# HTTP helper
# ==============================================================================


class SoarApiClient:
    """Thin wrapper around the SOAR REST API."""

    def __init__(self, base_url: str, auth_token: str, config: McpServerConfig) -> None:
        self._base_url = base_url.rstrip("/")
        self._auth_token = auth_token
        self._config = config
        self._session = requests.Session()
        self._session.headers.update({
            "ph-auth-token": auth_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        self._session.verify = config.ssl_verify

    def get(self, path: str, params: dict | None = None) -> tuple[dict | list | None, str | None]:
        """GET request. Returns (data, error_message)."""
        url = f"{self._base_url}/rest/{path.lstrip('/')}"
        try:
            resp = self._session.get(url, params=params, timeout=self._config.timeout)
            return self._handle_response(resp)
        except requests.exceptions.Timeout:
            return None, f"SOAR REST API timed out after {self._config.timeout}s"
        except requests.exceptions.SSLError as e:
            return None, f"SSL error: {e}"
        except requests.exceptions.ConnectionError as e:
            return None, f"Connection error: {e}"
        except Exception as e:
            return None, f"Unexpected error: {type(e).__name__}"

    def post(self, path: str, body: dict) -> tuple[dict | None, str | None]:
        """POST request. Returns (data, error_message)."""
        url = f"{self._base_url}/rest/{path.lstrip('/')}"
        try:
            resp = self._session.post(url, json=body, timeout=self._config.timeout)
            return self._handle_response(resp)
        except requests.exceptions.Timeout:
            return None, f"SOAR REST API timed out after {self._config.timeout}s"
        except requests.exceptions.ConnectionError as e:
            return None, f"Connection error: {e}"
        except Exception as e:
            return None, f"Unexpected error: {type(e).__name__}"

    def _handle_response(self, resp: requests.Response) -> tuple[Any, str | None]:
        if resp.status_code == 401:
            return None, "Authentication failed (HTTP 401). Check ph-auth-token in the MCP client config."
        if resp.status_code == 403:
            return None, "Access denied (HTTP 403). Token may lack required permissions."
        if resp.status_code == 404:
            return None, f"Resource not found (HTTP 404): {resp.url}"
        if resp.status_code >= 400:
            try:
                err_body = resp.json()
                msg = err_body.get("message") or err_body.get("error") or resp.text[:300]
            except Exception:
                msg = resp.text[:300]
            return None, f"SOAR API error HTTP {resp.status_code}: {msg}"
        try:
            return resp.json(), None
        except Exception:
            return {"raw": resp.text}, None


def _disclaimer() -> str:
    return (
        "\n\n---\n"
        "⚠️  Advisory: This data is provided for analysis only. "
        "Any write operations (notes, status changes, playbook runs) must be "
        "reviewed and confirmed by a human analyst before execution."
    )


def _fmt_case(c: dict) -> str:
    """Format a single case dict as readable text."""
    sev = c.get("severity", "unknown")
    status = c.get("status", "unknown")
    owner = c.get("owner_name") or c.get("owner") or "unassigned"
    label = c.get("label", "")
    tags = ", ".join(c.get("tags", []) or []) or "none"
    return (
        f"  ID: {c.get('id')} | {c.get('name', '(untitled)')}\n"
        f"    Status: {status} | Severity: {sev} | Owner: {owner} | Label: {label}\n"
        f"    Tags: {tags} | Created: {c.get('create_time', 'unknown')}"
    )


def _fmt_artifact(a: dict) -> str:
    """Format a single artifact as readable text."""
    cef = a.get("cef") or {}
    cef_str = ", ".join(f"{k}={v}" for k, v in list(cef.items())[:8]) if cef else "none"
    return (
        f"  ID: {a.get('id')} | Type: {a.get('type', 'unknown')} | "
        f"Name: {a.get('name', '(unnamed)')}\n"
        f"    CEF fields: {cef_str}\n"
        f"    Source: {a.get('source_data_identifier', 'unknown')} | "
        f"Created: {a.get('create_time', 'unknown')}"
    )


# ==============================================================================
# MCP Tool schema definitions
# ==============================================================================

TOOL_SCHEMAS: dict[str, dict] = {
    "list_cases": {
        "description": (
            "List SOAR cases (containers) with optional filters. "
            "Returns case ID, title, status, severity, owner, label, and tags. "
            "Use this to get an overview of open investigations or find cases matching specific criteria."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "description": "Filter by status: open, closed, resolved, new, in_progress. Leave empty for all.",
                    "enum": ["open", "closed", "resolved", "new", "in_progress", ""],
                },
                "severity": {
                    "type": "string",
                    "description": "Filter by severity: high, medium, low, informational. Leave empty for all.",
                    "enum": ["high", "medium", "low", "informational", ""],
                },
                "label": {
                    "type": "string",
                    "description": "Filter by case label/type (e.g. phishing, malware, incident).",
                },
                "owner": {
                    "type": "string",
                    "description": "Filter by owner username.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of cases to return (default: 20, max: 50).",
                    "default": 20,
                },
            },
        },
    },
    "get_case": {
        "description": (
            "Get full details of a specific SOAR case by ID. "
            "Returns title, description, status, severity, owner, tags, artifacts count, "
            "notes count, playbook runs, and all custom fields. "
            "Use this after identifying a case with list_cases or search_cases."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "integer",
                    "description": "The numeric SOAR container/case ID.",
                },
            },
            "required": ["case_id"],
        },
    },
    "search_cases": {
        "description": (
            "Search SOAR cases by keyword across title, description, and tags. "
            "Returns matching cases sorted by creation time (newest first). "
            "Useful for finding cases related to a specific threat, IOC, or incident."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search term to look for in case title and description.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results (default: 20).",
                    "default": 20,
                },
            },
            "required": ["query"],
        },
    },
    "list_artifacts": {
        "description": (
            "List all artifacts (IOCs, observables) associated with a SOAR case. "
            "Returns artifact ID, type, name, CEF fields (IP, domain, hash, URL, email, etc.), "
            "source, and creation time. "
            "Use this to see what indicators have been extracted or added to a case."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "integer",
                    "description": "The SOAR container/case ID to list artifacts for.",
                },
                "artifact_type": {
                    "type": "string",
                    "description": "Optional filter by CEF artifact type (e.g. ip, domain, hash, email, url).",
                },
            },
            "required": ["case_id"],
        },
    },
    "get_artifact": {
        "description": (
            "Get full details of a specific artifact by ID. "
            "Returns all CEF fields, tags, source, and associated case. "
            "Use this when you need the complete data for a specific IOC."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "artifact_id": {
                    "type": "integer",
                    "description": "The numeric SOAR artifact ID.",
                },
            },
            "required": ["artifact_id"],
        },
    },
    "list_case_notes": {
        "description": (
            "List all analyst notes and comments on a SOAR case. "
            "Returns note content, author, creation time. "
            "Use this to understand investigation history and analyst findings."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "integer",
                    "description": "The SOAR container/case ID.",
                },
            },
            "required": ["case_id"],
        },
    },
    "list_playbooks": {
        "description": (
            "List all available SOAR playbooks with name, description, category, and active status. "
            "Use this to discover what automated response or enrichment playbooks are available "
            "before recommending which one to run."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Optional filter by playbook category.",
                },
                "active_only": {
                    "type": "boolean",
                    "description": "Return only active playbooks (default: true).",
                    "default": True,
                },
            },
        },
    },
    "get_playbook_run": {
        "description": (
            "Get the status and results of a specific playbook run. "
            "Returns run status (running, success, failed), start/end time, "
            "action results, and any output data. "
            "Use this to check whether a playbook completed successfully."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {
                    "type": "integer",
                    "description": "The SOAR playbook run ID.",
                },
            },
            "required": ["run_id"],
        },
    },
    "list_action_runs": {
        "description": (
            "List recent action runs for a case, showing what automated actions have been executed, "
            "their status, app used, and results. "
            "Use this to understand what automated enrichment or response has already occurred."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "integer",
                    "description": "The SOAR container/case ID.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of action runs to return (default: 20).",
                    "default": 20,
                },
            },
            "required": ["case_id"],
        },
    },
    "list_users": {
        "description": (
            "List SOAR users with username, display name, email, and role. "
            "Use this when suggesting case assignments or identifying available analysts."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "role": {
                    "type": "string",
                    "description": "Optional filter by role name.",
                },
            },
        },
    },
    "get_soar_info": {
        "description": (
            "Get system information about this SOAR instance: "
            "version, license info, connected apps count, and overall health status."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    # ── Write tools ──────────────────────────────────────────────────────────
    "add_case_note": {
        "description": (
            "⚠️ WRITE OPERATION — Add a note or comment to a SOAR case. "
            "The note will be visible to all analysts with access to the case. "
            "Review the note content carefully before confirming."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "integer",
                    "description": "The SOAR container/case ID.",
                },
                "note": {
                    "type": "string",
                    "description": "The note text to add (supports Markdown).",
                },
                "title": {
                    "type": "string",
                    "description": "Optional note title/subject.",
                },
            },
            "required": ["case_id", "note"],
        },
    },
    "run_playbook": {
        "description": (
            "⚠️ WRITE OPERATION — Run a SOAR playbook on a specific case. "
            "This triggers automated actions that may modify case state, send alerts, "
            "or take response actions. ALWAYS confirm with the analyst before calling this tool."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "integer",
                    "description": "The SOAR container/case ID to run the playbook on.",
                },
                "playbook_id": {
                    "type": "integer",
                    "description": "The SOAR playbook ID to run.",
                },
                "scope": {
                    "type": "string",
                    "description": "Scope for the playbook run: new or all (default: new).",
                    "enum": ["new", "all"],
                    "default": "new",
                },
            },
            "required": ["case_id", "playbook_id"],
        },
    },
    "update_case_status": {
        "description": (
            "⚠️ WRITE OPERATION — Update the status of a SOAR case. "
            "Valid statuses: open, closed, resolved, new, in_progress."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "integer",
                    "description": "The SOAR container/case ID.",
                },
                "status": {
                    "type": "string",
                    "description": "New status value.",
                    "enum": ["open", "closed", "resolved", "new", "in_progress"],
                },
            },
            "required": ["case_id", "status"],
        },
    },
    "update_case_severity": {
        "description": (
            "⚠️ WRITE OPERATION — Update the severity of a SOAR case. "
            "Valid severities: high, medium, low, informational."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "integer",
                    "description": "The SOAR container/case ID.",
                },
                "severity": {
                    "type": "string",
                    "description": "New severity level.",
                    "enum": ["high", "medium", "low", "informational"],
                },
            },
            "required": ["case_id", "severity"],
        },
    },
    "update_case_owner": {
        "description": (
            "⚠️ WRITE OPERATION — Reassign a SOAR case to a different analyst."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "integer",
                    "description": "The SOAR container/case ID.",
                },
                "owner": {
                    "type": "string",
                    "description": "Username of the new owner/assignee.",
                },
            },
            "required": ["case_id", "owner"],
        },
    },
    "create_artifact": {
        "description": (
            "⚠️ WRITE OPERATION — Add a new artifact (IOC/observable) to a SOAR case. "
            "Provide at minimum the CEF field name and value (e.g. sourceAddress, fileHash)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "case_id": {
                    "type": "integer",
                    "description": "The SOAR container/case ID.",
                },
                "name": {
                    "type": "string",
                    "description": "Artifact name/label.",
                },
                "artifact_type": {
                    "type": "string",
                    "description": "CEF artifact type (e.g. ip, domain, hash, email, url, fileHash).",
                },
                "cef_data": {
                    "type": "object",
                    "description": "Key-value dict of CEF fields (e.g. {\"sourceAddress\": \"1.2.3.4\"}).",
                },
                "label": {
                    "type": "string",
                    "description": "Optional artifact label (default: artifact).",
                },
            },
            "required": ["case_id", "name", "artifact_type"],
        },
    },
}


# ==============================================================================
# Tool implementations
# ==============================================================================


def tool_list_cases(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """List SOAR cases with optional filters."""
    limit = min(int(args.get("limit") or 20), config.max_results)
    params: dict[str, Any] = {
        "_filter_status": f'"{args["status"]}"' if args.get("status") else None,
        "_filter_severity": f'"{args["severity"]}"' if args.get("severity") else None,
        "_filter_label": f'"{args["label"]}"' if args.get("label") else None,
        "_filter_owner_name": f'"{args["owner"]}"' if args.get("owner") else None,
        "page_size": limit,
        "sort": "create_time",
        "order": "desc",
    }
    params = {k: v for k, v in params.items() if v is not None}

    data, err = client.get("container", params=params)
    if err:
        return f"Error listing cases: {err}"

    items = data if isinstance(data, list) else data.get("data", [])

    # Apply min_severity filter if configured
    if config.min_severity:
        min_sev_val = _SEVERITY_ORDER.get(config.min_severity, 0)
        items = [c for c in items if _SEVERITY_ORDER.get(c.get("severity", "").lower(), 0) >= min_sev_val]

    # Apply allowed_labels filter if configured
    if config.allowed_labels:
        items = [c for c in items if c.get("label", "") in config.allowed_labels]

    if not items:
        return "No cases found matching the specified filters."

    lines = [f"Found {len(items)} case(s):\n"]
    for c in items[:limit]:
        lines.append(_fmt_case(c))
    result = "\n".join(lines)
    return result + (_disclaimer() if config.advisory_disclaimer else "")


def tool_get_case(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """Get full details of a specific case."""
    case_id = args.get("case_id")
    if not case_id:
        return "Error: case_id is required."

    data, err = client.get(f"container/{case_id}")
    if err:
        return f"Error fetching case {case_id}: {err}"
    if not isinstance(data, dict):
        return f"Unexpected response format for case {case_id}."

    # Fetch artifact count
    art_data, _ = client.get("artifact", params={"_filter_container_id": case_id, "page_size": 1})
    artifact_count = art_data.get("count", "unknown") if isinstance(art_data, dict) else "unknown"

    # Fetch note count
    note_data, _ = client.get("note", params={"_filter_container_id": case_id, "page_size": 1})
    note_count = note_data.get("count", "unknown") if isinstance(note_data, dict) else "unknown"

    tags = ", ".join(data.get("tags", []) or []) or "none"
    custom_fields = data.get("custom_fields") or {}

    lines = [
        f"Case #{case_id}: {data.get('name', '(untitled)')}",
        f"  Status:      {data.get('status', 'unknown')}",
        f"  Severity:    {data.get('severity', 'unknown')}",
        f"  Owner:       {data.get('owner_name') or data.get('owner') or 'unassigned'}",
        f"  Label:       {data.get('label', 'none')}",
        f"  Tags:        {tags}",
        f"  Created:     {data.get('create_time', 'unknown')}",
        f"  Updated:     {data.get('modify_time', 'unknown')}",
        f"  Artifacts:   {artifact_count}",
        f"  Notes:       {note_count}",
        f"  Description: {(data.get('description') or '(none)').strip()[:500]}",
    ]
    if custom_fields:
        lines.append("  Custom fields:")
        for k, v in list(custom_fields.items())[:10]:
            lines.append(f"    {k}: {v}")

    return "\n".join(lines) + (_disclaimer() if config.advisory_disclaimer else "")


def tool_search_cases(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """Search cases by keyword."""
    query = (args.get("query") or "").strip()
    if not query:
        return "Error: query is required."
    limit = min(int(args.get("limit") or 20), config.max_results)

    params = {
        "_filter_name__icontains": f'"{query}"',
        "page_size": limit,
        "sort": "create_time",
        "order": "desc",
    }
    data, err = client.get("container", params=params)
    if err:
        return f"Error searching cases: {err}"

    items = data if isinstance(data, list) else data.get("data", [])
    if not items:
        return f"No cases found matching '{query}'."

    lines = [f"Found {len(items)} case(s) matching '{query}':\n"]
    for c in items[:limit]:
        lines.append(_fmt_case(c))
    return "\n".join(lines) + (_disclaimer() if config.advisory_disclaimer else "")


def tool_list_artifacts(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """List artifacts for a case."""
    case_id = args.get("case_id")
    if not case_id:
        return "Error: case_id is required."
    art_type = args.get("artifact_type", "")
    limit = config.max_items_per_case

    params: dict = {
        "_filter_container_id": case_id,
        "page_size": limit,
    }
    if art_type:
        params["_filter_type__icontains"] = f'"{art_type}"'

    data, err = client.get("artifact", params=params)
    if err:
        return f"Error listing artifacts for case {case_id}: {err}"

    items = data if isinstance(data, list) else data.get("data", [])
    if not items:
        return f"No artifacts found for case {case_id}" + (f" of type '{art_type}'" if art_type else "") + "."

    lines = [f"Found {len(items)} artifact(s) for case #{case_id}:\n"]
    for a in items:
        lines.append(_fmt_artifact(a))
    return "\n".join(lines) + (_disclaimer() if config.advisory_disclaimer else "")


def tool_get_artifact(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """Get full details of a specific artifact."""
    artifact_id = args.get("artifact_id")
    if not artifact_id:
        return "Error: artifact_id is required."

    data, err = client.get(f"artifact/{artifact_id}")
    if err:
        return f"Error fetching artifact {artifact_id}: {err}"
    if not isinstance(data, dict):
        return f"Unexpected response for artifact {artifact_id}."

    cef = data.get("cef") or {}
    cef_lines = "\n".join(f"    {k}: {v}" for k, v in cef.items()) or "    (none)"
    tags = ", ".join(data.get("tags", []) or []) or "none"

    return (
        f"Artifact #{artifact_id}: {data.get('name', '(unnamed)')}\n"
        f"  Type:    {data.get('type', 'unknown')}\n"
        f"  Case:    #{data.get('container_id', 'unknown')}\n"
        f"  Source:  {data.get('source_data_identifier', 'unknown')}\n"
        f"  Tags:    {tags}\n"
        f"  Created: {data.get('create_time', 'unknown')}\n"
        f"  CEF fields:\n{cef_lines}"
    ) + (_disclaimer() if config.advisory_disclaimer else "")


def tool_list_case_notes(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """List analyst notes on a case."""
    case_id = args.get("case_id")
    if not case_id:
        return "Error: case_id is required."

    data, err = client.get("note", params={"_filter_container_id": case_id, "page_size": config.max_items_per_case})
    if err:
        return f"Error listing notes for case {case_id}: {err}"

    items = data if isinstance(data, list) else data.get("data", [])
    if not items:
        return f"No notes found for case #{case_id}."

    lines = [f"Notes for case #{case_id} ({len(items)} total):\n"]
    for n in items:
        title = n.get("title") or n.get("note_title") or "(untitled)"
        author = n.get("author") or "(unknown)"
        created = n.get("create_time") or n.get("modified_time") or "unknown"
        content = (n.get("note") or n.get("content") or "(empty)").strip()[:500]
        lines.append(f"  [{created}] {title} (by {author})")
        lines.append(f"    {content}")
        lines.append("")
    return "\n".join(lines)


def tool_list_playbooks(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """List available SOAR playbooks."""
    active_only = args.get("active_only", True)
    category = args.get("category", "")

    params: dict = {"page_size": config.max_results}
    if active_only:
        params["_filter_active"] = "true"
    if category:
        params["_filter_category__icontains"] = f'"{category}"'

    data, err = client.get("playbook", params=params)
    if err:
        return f"Error listing playbooks: {err}"

    items = data if isinstance(data, list) else data.get("data", [])
    if not items:
        return "No playbooks found."

    lines = [f"Available playbooks ({len(items)}):\n"]
    for pb in items:
        status = "active" if pb.get("active") else "inactive"
        lines.append(
            f"  ID: {pb.get('id')} | {pb.get('name', '(unnamed)')} [{status}]\n"
            f"    Category: {pb.get('category', 'none')} | "
            f"Repo: {pb.get('scm', 'local')}\n"
            f"    Description: {(pb.get('description') or '(none)')[:200]}"
        )
    return "\n".join(lines)


def tool_get_playbook_run(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """Get status and results of a playbook run."""
    run_id = args.get("run_id")
    if not run_id:
        return "Error: run_id is required."

    data, err = client.get(f"playbook_run/{run_id}")
    if err:
        return f"Error fetching playbook run {run_id}: {err}"
    if not isinstance(data, dict):
        return f"Unexpected response for run {run_id}."

    status = data.get("status", "unknown")
    playbook = data.get("playbook", {}) if isinstance(data.get("playbook"), dict) else {}
    pb_name = playbook.get("name", str(data.get("playbook_id", "unknown")))

    return (
        f"Playbook Run #{run_id}\n"
        f"  Playbook:    {pb_name}\n"
        f"  Status:      {status}\n"
        f"  Case:        #{data.get('container', data.get('container_id', 'unknown'))}\n"
        f"  Started:     {data.get('create_time', 'unknown')}\n"
        f"  Finished:    {data.get('update_time', data.get('end_time', 'still running'))}\n"
        f"  Message:     {data.get('message', '(none)')}"
    )


def tool_list_action_runs(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """List action runs for a case."""
    case_id = args.get("case_id")
    if not case_id:
        return "Error: case_id is required."
    limit = min(int(args.get("limit") or 20), config.max_results)

    data, err = client.get(
        "action_run",
        params={"_filter_container": case_id, "page_size": limit, "sort": "create_time", "order": "desc"},
    )
    if err:
        return f"Error listing action runs for case {case_id}: {err}"

    items = data if isinstance(data, list) else data.get("data", [])
    if not items:
        return f"No action runs found for case #{case_id}."

    lines = [f"Action runs for case #{case_id} ({len(items)} shown):\n"]
    for ar in items:
        lines.append(
            f"  [{ar.get('create_time', 'unknown')}] {ar.get('action', 'unknown')} "
            f"— {ar.get('app', {}).get('name', 'unknown') if isinstance(ar.get('app'), dict) else 'unknown'} "
            f"— Status: {ar.get('status', 'unknown')}"
        )
    return "\n".join(lines)


def tool_list_users(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """List SOAR users."""
    role = args.get("role", "")
    params: dict = {"page_size": config.max_results}
    if role:
        params["_filter_roles__name__icontains"] = f'"{role}"'

    data, err = client.get("ph_user", params=params)
    if err:
        return f"Error listing users: {err}"

    items = data if isinstance(data, list) else data.get("data", [])
    if not items:
        return "No users found."

    lines = [f"SOAR Users ({len(items)}):\n"]
    for u in items:
        roles = ", ".join(r.get("name", "") if isinstance(r, dict) else str(r) for r in (u.get("roles") or []))
        lines.append(
            f"  {u.get('username', '(unknown)')} | {u.get('first_name', '')} {u.get('last_name', '')} "
            f"| {u.get('email', '')} | Roles: {roles or 'none'}"
        )
    return "\n".join(lines)


def tool_get_soar_info(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """Get SOAR system info."""
    data, err = client.get("version")
    if err:
        return f"Error fetching SOAR version info: {err}"

    if not isinstance(data, dict):
        return "SOAR info received but in unexpected format."

    version = data.get("version", "unknown")
    build = data.get("build", "unknown")

    # Also fetch app count
    app_data, _ = client.get("app", params={"page_size": 1})
    app_count = app_data.get("count", "unknown") if isinstance(app_data, dict) else "unknown"

    return (
        f"Splunk SOAR Instance\n"
        f"  Version:  {version} (build {build})\n"
        f"  Apps installed: {app_count}\n"
        f"  REST API: {client._base_url}/rest\n"
        f"  MCP Endpoint: {client._base_url}/rest/handler/phantom_soar_mcp_server/mcp"
    )


# ── Write tools ────────────────────────────────────────────────────────────────

def tool_add_case_note(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """Add a note to a case."""
    case_id = args.get("case_id")
    note_text = (args.get("note") or "").strip()
    if not case_id or not note_text:
        return "Error: case_id and note are required."

    body = {
        "container_id": case_id,
        "note": note_text,
        "note_type": "general",
        "phase_id": 0,
        "title": (args.get("title") or "AI-Assisted Analysis Note").strip(),
    }
    data, err = client.post("note", body)
    if err:
        return f"Error adding note to case {case_id}: {err}"

    note_id = data.get("id", "unknown") if isinstance(data, dict) else "unknown"
    return (
        f"✅ Note added successfully to case #{case_id} (note ID: {note_id}).\n"
        f"Title: {body['title']}\n"
        f"Content: {note_text[:200]}{'...' if len(note_text) > 200 else ''}"
    ) + (_disclaimer() if config.advisory_disclaimer else "")


def tool_run_playbook(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """Run a playbook on a case."""
    case_id = args.get("case_id")
    playbook_id = args.get("playbook_id")
    if not case_id or not playbook_id:
        return "Error: case_id and playbook_id are required."

    scope = args.get("scope", "new")
    if scope not in ("new", "all"):
        scope = "new"

    body = {
        "container_id": case_id,
        "playbook_id": playbook_id,
        "scope": scope,
        "run": True,
    }
    data, err = client.post("playbook_run", body)
    if err:
        return f"Error running playbook {playbook_id} on case {case_id}: {err}"

    run_id = data.get("playbook_run_id", data.get("id", "unknown")) if isinstance(data, dict) else "unknown"
    return (
        f"✅ Playbook run started.\n"
        f"  Case: #{case_id} | Playbook: #{playbook_id} | Run ID: {run_id}\n"
        f"  Use get_playbook_run(run_id={run_id}) to check status."
    ) + (_disclaimer() if config.advisory_disclaimer else "")


def tool_update_case_status(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """Update case status."""
    case_id = args.get("case_id")
    status = (args.get("status") or "").lower()
    if not case_id or not status:
        return "Error: case_id and status are required."
    if status not in _VALID_STATUSES:
        return f"Error: Invalid status '{status}'. Valid: {', '.join(sorted(_VALID_STATUSES))}"

    data, err = client.post(f"container/{case_id}", {"status": status})
    if err:
        return f"Error updating status of case {case_id}: {err}"

    return f"✅ Case #{case_id} status updated to '{status}'." + (
        _disclaimer() if config.advisory_disclaimer else ""
    )


def tool_update_case_severity(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """Update case severity."""
    case_id = args.get("case_id")
    severity = (args.get("severity") or "").lower()
    if not case_id or not severity:
        return "Error: case_id and severity are required."
    if severity not in _VALID_SEVERITIES:
        return f"Error: Invalid severity '{severity}'. Valid: {', '.join(sorted(_VALID_SEVERITIES))}"

    data, err = client.post(f"container/{case_id}", {"severity": severity})
    if err:
        return f"Error updating severity of case {case_id}: {err}"

    return f"✅ Case #{case_id} severity updated to '{severity}'." + (
        _disclaimer() if config.advisory_disclaimer else ""
    )


def tool_update_case_owner(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """Update case owner."""
    case_id = args.get("case_id")
    owner = (args.get("owner") or "").strip()
    if not case_id or not owner:
        return "Error: case_id and owner are required."

    data, err = client.post(f"container/{case_id}", {"owner_name": owner})
    if err:
        return f"Error updating owner of case {case_id}: {err}"

    return f"✅ Case #{case_id} reassigned to '{owner}'." + (
        _disclaimer() if config.advisory_disclaimer else ""
    )


def tool_create_artifact(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """Create a new artifact on a case."""
    case_id = args.get("case_id")
    name = (args.get("name") or "").strip()
    art_type = (args.get("artifact_type") or "").strip()
    cef_data = args.get("cef_data") or {}
    if not case_id or not name or not art_type:
        return "Error: case_id, name, and artifact_type are required."
    if not isinstance(cef_data, dict):
        cef_data = {}

    body = {
        "container_id": case_id,
        "name": name,
        "label": args.get("label", "artifact"),
        "type": art_type,
        "cef": cef_data,
        "source_data_identifier": f"mcp_created_{name}",
    }
    data, err = client.post("artifact", body)
    if err:
        return f"Error creating artifact on case {case_id}: {err}"

    art_id = data.get("id", "unknown") if isinstance(data, dict) else "unknown"
    return (
        f"✅ Artifact created on case #{case_id} (artifact ID: {art_id}).\n"
        f"  Name: {name} | Type: {art_type}"
    ) + (_disclaimer() if config.advisory_disclaimer else "")


# ==============================================================================
# Dispatcher
# ==============================================================================

_TOOL_HANDLERS = {
    "list_cases": tool_list_cases,
    "get_case": tool_get_case,
    "search_cases": tool_search_cases,
    "list_artifacts": tool_list_artifacts,
    "get_artifact": tool_get_artifact,
    "list_case_notes": tool_list_case_notes,
    "list_playbooks": tool_list_playbooks,
    "get_playbook_run": tool_get_playbook_run,
    "list_action_runs": tool_list_action_runs,
    "list_users": tool_list_users,
    "get_soar_info": tool_get_soar_info,
    # Write tools
    "add_case_note": tool_add_case_note,
    "run_playbook": tool_run_playbook,
    "update_case_status": tool_update_case_status,
    "update_case_severity": tool_update_case_severity,
    "update_case_owner": tool_update_case_owner,
    "create_artifact": tool_create_artifact,
}


def call_tool(
    tool_name: str,
    arguments: dict,
    client: SoarApiClient,
    config: McpServerConfig,
) -> str:
    """
    Dispatch a tool call to its implementation.

    Returns a text string as the MCP content response.
    Never raises; errors are returned as text.
    """
    handler = _TOOL_HANDLERS.get(tool_name)
    if handler is None:
        return f"Unknown tool: '{tool_name}'"
    try:
        result = handler(client, config, arguments or {})
        if config.log_tool_calls:
            logger.info("[MCP Tool] Called '%s' with args=%s", tool_name, list((arguments or {}).keys()))
        return result
    except Exception as exc:
        logger.exception("[MCP Tool] Unexpected error in tool '%s': %s", tool_name, exc)
        return f"Internal error executing tool '{tool_name}': {type(exc).__name__}"
