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

import hashlib
import json
import logging
import re
import secrets
import textwrap
import threading
import time
from typing import Any, Optional

import requests

from soar_mcp_config import READ_ONLY_TOOLS, McpServerConfig

# ── Security constants ─────────────────────────────────────────────────────────
_MAX_NOTE_LENGTH = 10_000   # characters — prevents storage exhaustion (issue #11)
_HTML_TAG_RE = re.compile(r'<[^>]+>')  # used to strip HTML from note content


def _require_positive_int(value: Any, name: str) -> tuple[int | None, str | None]:
    """
    Validate that *value* is (or can be cast to) a positive integer.

    Returns (int_value, None) on success or (None, error_string) on failure.
    Prevents path-traversal attacks where string IDs like '1/../../ph_user' are
    interpolated directly into REST API URLs (security issue #9).
    """
    try:
        v = int(value)
        if v <= 0:
            raise ValueError
        return v, None
    except (TypeError, ValueError):
        return None, f"Error: {name} must be a positive integer, got: {value!r}"


def _safe_filter_value(value: Any, *, max_len: int = 200) -> str:
    """Sanitize a free-text value before embedding it in a SOAR `_filter_*`
    expression (issue #49).

    The values are wrapped in double quotes and passed as `_filter_*` params;
    an embedded quote or backslash could break out of / alter the filter
    expression. Strip both and cap the length. Read-only tools stay within the
    caller's token scope, so this is defensive hardening against malformed or
    filter-manipulating input rather than privilege escalation.
    """
    return str(value).replace("\\", "").replace('"', "")[:max_len]


# ── REST/COA error classification (issue #70) ─────────────────────────────────
# Turns HTTP responses and request exceptions into a structured, credential-safe
# error record: category, endpoint_category, status_code, safe_message,
# suggested_next_step. Never includes tokens, headers, or raw response bodies.

_STATUS_CATEGORY = {401: "authentication", 403: "authorization", 404: "not_found"}
_CATEGORY_HINT = {
    "authentication": "Verify the ph-auth-token in your MCP client configuration.",
    "authorization": "The token user may lack the required SOAR role/permission "
                     "(check Administration → Audit).",
    "not_found": "Verify the resource ID, or whether this endpoint exists on this "
                 "SOAR version.",
    "server_error": "Transient SOAR-side error — retry shortly or check SOAR logs.",
    "client_error": "Check the request parameters.",
    "timeout": "Increase [server] timeout or check SOAR responsiveness.",
    "tls": "Add the SOAR certificate to the trust store, or set ssl_verify=false on "
           "test instances only.",
    "connection": "Verify base_url and network reachability to SOAR.",
    "unknown": "Check the SOAR logs for details.",
}


def _endpoint_category(url: str) -> str:
    """Coarse endpoint label (no IDs/secrets) for diagnostics."""
    try:
        after = url.split("://", 1)[-1]
        path = after.split("/", 1)[1] if "/" in after else ""
        for root in ("rest/", "coa/"):
            if root in path:
                seg = path.split(root, 1)[1].split("/", 1)[0].split("?")[0]
                return f"{root.rstrip('/')}/{seg}" if seg else root.rstrip("/")
    except Exception:
        pass
    return ""


def _soar_message(resp: "requests.Response") -> str:
    """Return ONLY the SOAR message/error field — never raw text/HTML bodies."""
    try:
        body = resp.json()
        if isinstance(body, dict):
            m = body.get("message") or body.get("error")
            if m:
                return str(m)[:300]
    except Exception:
        pass
    return ""


def classify_response(resp: "requests.Response") -> dict:
    """Classify a >=400 HTTP response into a safe error record."""
    sc = resp.status_code
    cat = _STATUS_CATEGORY.get(sc) or ("server_error" if sc >= 500 else "client_error")
    base = {
        401: "Authentication failed (HTTP 401).",
        403: "Access denied (HTTP 403).",
        404: "Resource not found (HTTP 404).",
    }.get(sc, f"SOAR API error (HTTP {sc}).")
    soar_msg = _soar_message(resp)
    safe = f"{base} {soar_msg}".strip() if soar_msg else base
    return {
        "category": cat,
        "endpoint_category": _endpoint_category(getattr(resp, "url", "") or ""),
        "status_code": sc,
        "safe_message": safe,
        "suggested_next_step": _CATEGORY_HINT[cat],
    }


def classify_exception(exc: Exception, *, where: str = "SOAR REST API") -> dict:
    """Classify a request exception into a safe error record (keeps keyword
    substrings like 'timed out' / 'SSL error' / 'Connection error' for callers
    that pattern-match on them)."""
    if isinstance(exc, requests.exceptions.Timeout):
        cat, safe = "timeout", f"{where} timed out."
    elif isinstance(exc, requests.exceptions.SSLError):
        cat, safe = "tls", "SSL error: TLS certificate verification failed."
    elif isinstance(exc, requests.exceptions.ConnectionError):
        cat, safe = "connection", f"Connection error: could not reach {where}."
    else:
        cat, safe = "unknown", f"Unexpected error: {type(exc).__name__}"
    return {
        "category": cat,
        "endpoint_category": "",
        "status_code": None,
        "safe_message": safe,
        "suggested_next_step": _CATEGORY_HINT[cat],
    }


def _err_str(info: dict) -> str:
    """Render an error record as a single safe string."""
    return f"{info['safe_message']} {info['suggested_next_step']}".strip()


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
        except Exception as e:
            return None, _err_str(classify_exception(e, where="SOAR REST API"))

    def post(self, path: str, body: dict) -> tuple[dict | None, str | None]:
        """POST request. Returns (data, error_message)."""
        url = f"{self._base_url}/rest/{path.lstrip('/')}"
        try:
            resp = self._session.post(url, json=body, timeout=self._config.timeout)
            return self._handle_response(resp)
        except Exception as e:
            return None, _err_str(classify_exception(e, where="SOAR REST API"))

    def post_multipart(
        self,
        path: str,
        files: dict,
        data: dict | None = None,
    ) -> tuple[dict | None, str | None]:
        """POST multipart/form-data (file upload).  Used by import_playbook."""
        url = f"{self._base_url}/rest/{path.lstrip('/')}"
        try:
            resp = self._session.post(
                url,
                files=files,
                data=data or {},
                timeout=self._config.timeout,
                verify=self._config.ssl_verify,
            )
            return self._handle_response(resp)
        except Exception as e:
            return None, _err_str(classify_exception(e, where="SOAR REST API"))

    def delete(self, path: str) -> tuple[dict | None, str | None]:
        """DELETE request. Returns (data, error_message)."""
        url = f"{self._base_url}/rest/{path.lstrip('/')}"
        try:
            resp = self._session.delete(url, timeout=self._config.timeout)
            return self._handle_response(resp)
        except Exception as e:
            return None, _err_str(classify_exception(e, where="SOAR REST API"))

    def get_binary(self, path: str, params: dict | None = None) -> tuple[bytes | None, str | None]:
        """GET request returning raw bytes (for binary endpoints like playbook export)."""
        url = f"{self._base_url}/rest/{path.lstrip('/')}"
        try:
            resp = self._session.get(url, params=params, timeout=self._config.timeout)
            if resp.status_code >= 400:
                info = classify_response(resp)
                logger.info("[MCP] get_binary HTTP %s body=%s", resp.status_code, resp.text[:200])
                return None, _err_str(info)
            return resp.content, None
        except Exception as e:
            return None, _err_str(classify_exception(e, where="SOAR REST API"))

    def _coa_get(self, path: str, params: dict | None = None) -> tuple[dict | list | None, str | None]:
        """GET from the COA Visual Editor endpoint — does NOT prepend /rest/.

        The COA endpoint lives at /coa/... on the same host as /rest/...
        Example: https://soar.example.com/rest -> https://soar.example.com/coa/playbooks/123

        # VERIFY: Auth header behaviour on /coa/ paths — same ph-auth-token accepted?
        # VERIFY: Does /coa/playbooks/{id} return 401/403/404 with same JSON structure?
        # VERIFY: Is the base hostname the same (only path root differs)?
        """
        base = self._base_url  # e.g. https://soar.example.com/rest
        if base.endswith("/rest"):
            base = base[:-5]
        elif "/rest/" in base:
            base = base[: base.index("/rest/")]
        url = f"{base}/coa/{path.lstrip('/')}"
        try:
            resp = self._session.get(url, params=params, timeout=self._config.timeout)
            return self._handle_response(resp)
        except Exception as e:
            return None, _err_str(classify_exception(e, where="COA endpoint"))

    def _handle_response(self, resp: requests.Response) -> tuple[Any, str | None]:
        if resp.status_code >= 400:
            info = classify_response(resp)
            # Log the raw body server-side only (never returned to the client).
            if resp.status_code >= 500 or info["category"] == "client_error":
                logger.info("[MCP] HTTP %s body=%s", resp.status_code, resp.text[:200])
            return None, _err_str(info)
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
                    "description": "Filter by status: open, closed, resolved, new. Leave empty for all.",
                    "enum": ["open", "closed", "resolved", "new", ""],
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
            "Valid statuses: open, closed, resolved, new."
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
                    "enum": ["open", "closed", "resolved", "new"],
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
    # ── Playbook-Discovery & Build tools (v1.6.0+) ────────────────────────────
    "list_apps": {
        "description": (
            "List installed SOAR apps/connectors. "
            "Returns app ID, name, publisher, product name, and supported action names. "
            "Use this to discover which connectors are available before building a playbook."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name_contains": {
                    "type": "string",
                    "description": "Optional substring filter applied client-side to app name or product name (case-insensitive).",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results (default: 50).",
                    "default": 50,
                },
            },
        },
    },
    "list_assets": {
        "description": (
            "List configured SOAR assets (connector instances). "
            "Returns asset ID, name, linked app ID, product name, and configuration status. "
            "Actions are dispatched against assets (not apps) — use this after list_apps to "
            "find which asset to target in a playbook action block."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "app_id": {
                    "type": "integer",
                    "description": "Filter assets by app ID (from list_apps). Leave empty for all assets.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results (default: 50).",
                    "default": 50,
                },
            },
        },
    },
    "get_action_schema": {
        "description": (
            "Get detailed input parameters and output datapaths for actions of a SOAR app. "
            "Returns for each action: parameter names, data types, required flag, contains tags, "
            "and output datapaths (e.g. action_result.summary.malicious). "
            "Use this after list_apps to understand what inputs an action needs and which datapath "
            "to reference in a playbook decision block."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "app_id": {
                    "type": "integer",
                    "description": "App ID from list_apps. At least one of app_id or action_name is required.",
                },
                "action_name": {
                    "type": "string",
                    "description": "Filter to actions matching this name substring (case-insensitive). If app_id is omitted, also used to search for the app.",
                },
            },
        },
    },
    "export_playbook": {
        "description": (
            "Export a SOAR playbook as a base64-encoded gzip TAR archive (.tgz). "
            "The archive contains the playbook's blockly graph, which is the structural "
            "ground-truth used by the Visual Playbook Editor (VPE) and the playbook-builder skill. "
            "Use a known-good playbook as a golden template before generating a new one."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "playbook_id": {
                    "type": "integer",
                    "description": "Numeric SOAR playbook ID (from list_playbooks).",
                },
            },
            "required": ["playbook_id"],
        },
    },
    "import_playbook": {
        "description": (
            "Import a playbook archive into SOAR so it appears and is editable in the "
            "Visual Playbook Editor (VPE). Accepts a base64-encoded gzip TAR archive "
            "(as returned by export_playbook). "
            "WRITE operation — disabled by default. Enable in asset config and mcp.conf."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "archive_b64": {
                    "type": "string",
                    "description": "Base64-encoded gzip TAR archive of the playbook (output of export_playbook or generated by skill).",
                },
                "scm": {
                    "type": "string",
                    "description": "Source Control Management repo name to import into (default: 'local').",
                    "default": "local",
                },
                "force": {
                    "type": "boolean",
                    "description": "Overwrite existing playbook with the same name (default: false).",
                    "default": False,
                },
            },
            "required": ["archive_b64"],
        },
    },
    "create_container": {
        "description": (
            "Create a labeled SOAR container (case) for isolated playbook self-testing. "
            "The container is tagged with the supplied label so it can be identified and "
            "cleaned up after testing. Never use this against real case queues. "
            "WRITE operation — disabled by default. Also requires enable_test_harness = true "
            "in [safety] of mcp.conf as an additional safety gate."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Container name (e.g. 'test_url_rep_2026-07-09').",
                },
                "label": {
                    "type": "string",
                    "description": "Container label/type (default: 'test'). Use a dedicated test label to keep test cases separate.",
                    "default": "test",
                },
                "severity": {
                    "type": "string",
                    "description": "Severity level (default: 'low').",
                    "enum": ["high", "medium", "low", "informational"],
                    "default": "low",
                },
            },
            "required": ["name"],
        },
    },
    # ── COA Visual Editor tools (v1.6.3+) ──────────────────────────────────────
    "resolve_playbook_current_id": {
        "description": (
            "Resolve any playbook ID (current or stale) to the current Visual Editor draft. "
            "Returns input_id, current_id, is_current, version, previous_versions, name, and "
            "a stale warning when the input is an older revision. "
            "Use this before any COA-based operation to ensure you target the right draft."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "playbook_id": {
                    "type": "integer",
                    "description": "Playbook ID to resolve (may be current or a previous revision).",
                },
            },
            "required": ["playbook_id"],
        },
    },
    "get_playbook_identity_map": {
        "description": (
            "Return a complete version chain for a playbook — all known revision IDs "
            "sorted by version, with the current draft clearly marked. "
            "Accepts either a playbook name (exact match) or a numeric ID."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "playbook": {
                    "type": "string",
                    "description": "Exact playbook name to look up all versions for.",
                },
                "playbook_id": {
                    "type": "integer",
                    "description": "Any playbook ID (current or stale) — name is resolved from this.",
                },
            },
        },
    },
    "get_playbook_coa_summary": {
        "description": (
            "Return a compact, structured COA graph summary for the current Visual Editor draft. "
            "Includes node count, edge count, custom-name count, warning/error counts, "
            "input/output specs, trigger type, validation status, and utility block metadata. "
            "Does not require downloading a full export archive."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "playbook_id": {
                    "type": "integer",
                    "description": "Playbook ID to summarise (current or stale — resolved automatically).",
                },
            },
            "required": ["playbook_id"],
        },
    },
    "list_playbook_nodes": {
        "description": (
            "List the COA nodes (action, code, decision, prompt, format, start, end, etc.) "
            "for the current Visual Editor draft in a structured JSON format. "
            "Sorted by visual position (y, x, id). Sensitive parameter values are redacted."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "playbook_id": {
                    "type": "integer",
                    "description": "Playbook ID (current or stale — resolved automatically).",
                },
                "include_parameters": {
                    "type": "boolean",
                    "description": "Include node parameter values (redacted for sensitive keys). Default: false.",
                    "default": False,
                },
                "type_filter": {
                    "type": "string",
                    "description": "Return only nodes of this type (e.g. action, code, decision, start, end).",
                },
                "function_name_contains": {
                    "type": "string",
                    "description": "Return only nodes whose functionName contains this substring.",
                },
            },
            "required": ["playbook_id"],
        },
    },
    "list_playbook_edges": {
        "description": (
            "List the COA edges (connections) for the current Visual Editor draft. "
            "Each edge includes source node, target node, branch condition, and edge type. "
            "Sorted by source, target, then id."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "playbook_id": {
                    "type": "integer",
                    "description": "Playbook ID (current or stale — resolved automatically).",
                },
                "edge_from": {
                    "type": "string",
                    "description": "Return only edges from this source function name.",
                },
                "edge_to": {
                    "type": "string",
                    "description": "Return only edges to this target function name.",
                },
            },
            "required": ["playbook_id"],
        },
    },
    "check_saved_generated_python_drift": {
        "description": (
            "Detect drift between the Python saved on disk and what SOAR would regenerate "
            "from the COA userCode blocks. Helper functions defined outside userCode blocks "
            "are silently dropped when the Visual Editor saves the playbook. "
            "Returns a list of external_helper_candidates that are at risk."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "playbook_id": {
                    "type": "integer",
                    "description": "Playbook ID (current or stale — resolved automatically).",
                },
            },
            "required": ["playbook_id"],
        },
    },
    "check_datapath_selectability": {
        "description": (
            "Check whether a datapath from a producer action is selectable in the VPE "
            "for a specific consumer parameter, using contains-tag schema matching. "
            "Returns selectable (true/false/unknown), reason, and both contains-tag lists. "
            "Phase A: schema-only; edge provenance is not checked."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "producer_app_id": {
                    "type": "integer",
                    "description": "App ID of the action that produces the data.",
                },
                "producer_action": {
                    "type": "string",
                    "description": "Action name of the producer.",
                },
                "consumer_app_id": {
                    "type": "integer",
                    "description": "App ID of the action that consumes the data.",
                },
                "consumer_action": {
                    "type": "string",
                    "description": "Action name of the consumer.",
                },
                "consumer_parameter": {
                    "type": "string",
                    "description": "Parameter name of the consumer to check selectability for.",
                },
                "datapath": {
                    "type": "string",
                    "description": "Optional datapath to match against producer output (e.g. action_result.data.*.JobID).",
                },
            },
            "required": ["producer_app_id", "producer_action", "consumer_app_id", "consumer_action", "consumer_parameter"],
        },
    },
    "diff_playbook_versions": {
        "description": (
            "Semantic diff between two playbook revisions. "
            "Strips volatile fields (hash, timestamps) and categorizes each changed path "
            "as: layout (x/y only), metadata, graph_structure, parameter, code_usercode, "
            "validation_relevant, or wrapper. Returns is_layout_only flag."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "old_id": {
                    "type": "integer",
                    "description": "Playbook ID of the older revision.",
                },
                "new_id": {
                    "type": "integer",
                    "description": "Playbook ID of the newer revision.",
                },
            },
            "required": ["old_id", "new_id"],
        },
    },
    "verify_layout_only_change": {
        "description": (
            "Strict pass/fail check that only node x/y positions changed between two playbook revisions. "
            "Returns ok=true only when change_categories contains exclusively 'layout'. "
            "Any normalization error returns ok=false. "
            "This is the safety gate required before save_playbook_layout_only."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "before_id": {
                    "type": "integer",
                    "description": "Playbook ID before the layout change.",
                },
                "after_id": {
                    "type": "integer",
                    "description": "Playbook ID after the layout change.",
                },
            },
            "required": ["before_id", "after_id"],
        },
    },
    "validate_playbook_bundle": {
        "description": (
            "Run a multi-check validation bundle on a playbook: "
            "structure validation, native passed_validation flag, COA node warnings, "
            "Python py_compile (AST parse only — no execution), and optional lint. "
            "Each check returns passed/failed/skipped. skipped != passed."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "playbook_id": {
                    "type": "integer",
                    "description": "Playbook ID to validate (current or stale — resolved automatically).",
                },
            },
            "required": ["playbook_id"],
        },
    },
    "check_visual_editor_compat": {
        "description": (
            "Aggregate Visual Editor compatibility check. Fans out to: current-ID resolution, "
            "COA summary, node/edge listing, Python drift detection, and validation bundle. "
            "Returns a unified ok/warn/fail verdict with finding codes "
            "(stale_id, custom_name_count, node_warnings, node_errors, "
            "saved_generated_python_drift, validation_failed, validation_skipped). "
            "strict=true makes any medium finding also cause ok=false."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "playbook_id": {
                    "type": "integer",
                    "description": "Playbook ID to check (current or stale — resolved automatically).",
                },
                "strict": {
                    "type": "boolean",
                    "description": "If true, medium-severity findings also set ok=false. Default: false.",
                    "default": False,
                },
            },
            "required": ["playbook_id"],
        },
    },
    "save_playbook_layout_only": {
        "description": (
            "WRITE — Save node x/y position changes to a Visual Editor playbook. "
            "Requires verify_layout_only_change to pass first. "
            "dry_run=true (the default) shows what would be written without writing. "
            "Set dry_run=false only after reviewing the dry-run output. "
            "IMPORTANT: The COA write endpoint is not yet live-verified; "
            "actual writes return an error with instructions until VERIFICATION.md is updated."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "playbook_id": {
                    "type": "integer",
                    "description": "Playbook ID (must be the current draft — stale IDs are rejected).",
                },
                "node_positions": {
                    "type": "object",
                    "description": "Map of functionId -> {x: int, y: int} for nodes to reposition.",
                },
                "expected_hash": {
                    "type": "string",
                    "description": "Optional hash of the current COA state for pre-write verification.",
                },
                "dry_run": {
                    "type": "boolean",
                    "description": "Preview changes without writing. Default: true (always dry-run first).",
                    "default": True,
                },
            },
            "required": ["playbook_id", "node_positions"],
        },
    },
}


# ==============================================================================
# Tool implementations
# ==============================================================================


def _case_in_scope(case: dict, config: McpServerConfig) -> bool:
    """Return True if a case passes the configured MCP access controls
    (min_severity and allowed_labels).

    Enforced consistently across ALL case-accessing tools so the controls
    cannot be bypassed via get_case/search_cases/list_artifacts/list_case_notes
    (issue #41).
    """
    if config.min_severity:
        min_sev = _SEVERITY_ORDER.get(config.min_severity, 0)
        if _SEVERITY_ORDER.get((case.get("severity") or "").lower(), 0) < min_sev:
            return False
    if config.allowed_labels:
        if (case.get("label") or "") not in config.allowed_labels:
            return False
    return True


def _scope_guard(client: SoarApiClient, config: McpServerConfig, case_id: int) -> Optional[str]:
    """Return an error string if the parent case is outside MCP scope, else None.

    Used by child-object tools (list_artifacts, list_case_notes) so they cannot
    be used to read data from cases the label/severity controls forbid (#41).
    Only fetches the parent case when access controls are actually configured;
    fails open on a transient fetch error (SOAR token remains the primary auth).
    """
    if not (config.min_severity or config.allowed_labels):
        return None
    case, err = client.get(f"container/{case_id}")
    if err or not isinstance(case, dict):
        return None
    if not _case_in_scope(case, config):
        return f"Case #{case_id} is outside the MCP-allowed scope (label/severity restriction)."
    return None


def tool_list_cases(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """List SOAR cases with optional filters."""
    limit = min(int(args.get("limit") or 20), config.max_results)

    # min_severity is a range and allowed_labels is a set — neither maps cleanly
    # to a single SOAR _filter param, so they are enforced client-side. Fetch up
    # to max_results (not just `limit`) before filtering, otherwise pagination
    # would truncate the result set BEFORE the safety filters run and hide
    # matching cases (issue #63).
    scope_filtering = bool(config.min_severity or config.allowed_labels)
    page_size = config.max_results if scope_filtering else limit

    params: dict[str, Any] = {
        "_filter_status": f'"{_safe_filter_value(args["status"])}"' if args.get("status") else None,
        "_filter_severity": f'"{_safe_filter_value(args["severity"])}"' if args.get("severity") else None,
        "_filter_label": f'"{_safe_filter_value(args["label"])}"' if args.get("label") else None,
        "_filter_owner_name": f'"{_safe_filter_value(args["owner"])}"' if args.get("owner") else None,
        "page_size": page_size,
        "sort": "create_time",
        "order": "desc",
    }
    params = {k: v for k, v in params.items() if v is not None}

    data, err = client.get("container", params=params)
    if err:
        return f"Error listing cases: {err}"

    items = data if isinstance(data, list) else data.get("data", [])
    total = data.get("count", len(items)) if isinstance(data, dict) else len(items)

    # Apply the configured access controls (min_severity + allowed_labels).
    if scope_filtering:
        items = [c for c in items if _case_in_scope(c, config)]

    if not items:
        return "No cases found matching the specified filters."

    shown = items[:limit]
    suffix = f" (showing {len(shown)} of {len(items)} matching — use filters to narrow)" if len(items) > limit else ""
    lines = [f"Found {len(shown)} case(s){suffix}:\n"]
    for c in shown:
        lines.append(_fmt_case(c))
    result = "\n".join(lines)
    return result + (_disclaimer() if config.advisory_disclaimer else "")


def tool_get_case(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """Get full details of a specific case."""
    case_id, err_msg = _require_positive_int(args.get("case_id"), "case_id")
    if err_msg:
        return err_msg

    data, err = client.get(f"container/{case_id}")
    if err:
        return f"Error fetching case {case_id}: {err}"
    if not isinstance(data, dict):
        return f"Unexpected response format for case {case_id}."

    # Enforce the configured MCP access controls (issue #41) — a case outside
    # the allowed labels / below min_severity must not be readable by ID either.
    if not _case_in_scope(data, config):
        return f"Case #{case_id} is outside the MCP-allowed scope (label/severity restriction)."

    # Fetch artifact count
    art_data, _ = client.get("artifact", params={"_filter_container_id": case_id, "page_size": 1})
    artifact_count = art_data.get("count", "unknown") if isinstance(art_data, dict) else "unknown"

    # Fetch note count
    note_data, _ = client.get("note", params={"_filter_container_id": case_id, "page_size": 1})
    note_count = note_data.get("count", "unknown") if isinstance(note_data, dict) else "unknown"

    tags = ", ".join(data.get("tags", []) or []) or "none"
    custom_fields = data.get("custom_fields") or {}

    # SOAR may use different field names for the modification timestamp (bug #8)
    updated = (
        data.get("modify_time")
        or data.get("update_time")
        or data.get("modified_time")
        or "unknown"
    )

    lines = [
        f"Case #{case_id}: {data.get('name', '(untitled)')}",
        f"  Status:      {data.get('status', 'unknown')}",
        f"  Severity:    {data.get('severity', 'unknown')}",
        f"  Owner:       {data.get('owner_name') or data.get('owner') or 'unassigned'}",
        f"  Label:       {data.get('label', 'none')}",
        f"  Tags:        {tags}",
        f"  Created:     {data.get('create_time', 'unknown')}",
        f"  Updated:     {updated}",
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

    # Fetch up to max_results so the client-side scope filter (issue #41) does
    # not run on a prematurely truncated page.
    scope_filtering = bool(config.min_severity or config.allowed_labels)
    params = {
        "_filter_name__icontains": f'"{_safe_filter_value(query)}"',
        "page_size": config.max_results if scope_filtering else limit,
        "sort": "create_time",
        "order": "desc",
    }
    data, err = client.get("container", params=params)
    if err:
        return f"Error searching cases: {err}"

    items = data if isinstance(data, list) else data.get("data", [])
    # Enforce the configured MCP access controls (issue #41).
    if scope_filtering:
        items = [c for c in items if _case_in_scope(c, config)]
    if not items:
        return f"No cases found matching '{query}'."

    shown = items[:limit]
    suffix = f" (showing {len(shown)} of {len(items)} matching — refine query for more)" if len(items) > limit else ""
    lines = [f"Found {len(shown)} case(s) matching '{query}'{suffix}:\n"]
    for c in shown:
        lines.append(_fmt_case(c))
    return "\n".join(lines) + (_disclaimer() if config.advisory_disclaimer else "")


def tool_list_artifacts(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """List artifacts for a case."""
    case_id, err_msg = _require_positive_int(args.get("case_id"), "case_id")
    if err_msg:
        return err_msg
    scope_err = _scope_guard(client, config, case_id)
    if scope_err:
        return scope_err
    art_type = args.get("artifact_type", "")
    limit = config.max_items_per_case

    params: dict = {
        "_filter_container_id": case_id,
        "page_size": limit,
    }
    if art_type:
        params["_filter_type__icontains"] = f'"{_safe_filter_value(art_type)}"'

    data, err = client.get("artifact", params=params)
    if err:
        return f"Error listing artifacts for case {case_id}: {err}"

    items = data if isinstance(data, list) else data.get("data", [])
    total = data.get("count", len(items)) if isinstance(data, dict) else len(items)
    if not items:
        return f"No artifacts found for case {case_id}" + (f" of type '{art_type}'" if art_type else "") + "."

    suffix = f" (showing {len(items)} of {total} — use artifact_type to narrow)" if total > limit else ""
    lines = [f"Found {len(items)} artifact(s) for case #{case_id}{suffix}:\n"]
    for a in items:
        lines.append(_fmt_artifact(a))
    return "\n".join(lines) + (_disclaimer() if config.advisory_disclaimer else "")


def tool_get_artifact(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """Get full details of a specific artifact."""
    artifact_id, err_msg = _require_positive_int(args.get("artifact_id"), "artifact_id")
    if err_msg:
        return err_msg

    data, err = client.get(f"artifact/{artifact_id}")
    if err:
        return f"Error fetching artifact {artifact_id}: {err}"
    if not isinstance(data, dict):
        return f"Unexpected response for artifact {artifact_id}."

    cef = data.get("cef") or {}
    cef_lines = "\n".join(f"    {k}: {v}" for k, v in cef.items()) or "    (none)"
    tags = ", ".join(data.get("tags", []) or []) or "none"

    # SOAR returns the linked case as 'container' (not 'container_id') (bug #3)
    container = data.get("container") or data.get("container_id") or "unknown"

    return (
        f"Artifact #{artifact_id}: {data.get('name', '(unnamed)')}\n"
        f"  Type:    {data.get('type', 'unknown')}\n"
        f"  Case:    #{container}\n"
        f"  Source:  {data.get('source_data_identifier', 'unknown')}\n"
        f"  Tags:    {tags}\n"
        f"  Created: {data.get('create_time', 'unknown')}\n"
        f"  CEF fields:\n{cef_lines}"
    ) + (_disclaimer() if config.advisory_disclaimer else "")


def tool_list_case_notes(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """List analyst notes on a case."""
    case_id, err_msg = _require_positive_int(args.get("case_id"), "case_id")
    if err_msg:
        return err_msg
    scope_err = _scope_guard(client, config, case_id)
    if scope_err:
        return scope_err

    data, err = client.get("note", params={"_filter_container_id": case_id, "page_size": config.max_items_per_case})
    if err:
        return f"Error listing notes for case {case_id}: {err}"

    items = data if isinstance(data, list) else data.get("data", [])
    total = data.get("count", len(items)) if isinstance(data, dict) else len(items)
    if not items:
        return f"No notes found for case #{case_id}."

    count_label = f"{len(items)} of {total}" if total > len(items) else str(len(items))
    lines = [f"Notes for case #{case_id} ({count_label} total):\n"]
    for n in items:
        title = n.get("title") or n.get("note_title") or "(untitled)"
        # SOAR returns the author as a numeric user ID in the 'author' field (bug #6).
        # If author_name is absent, fall back gracefully with a user# prefix.
        author_raw = n.get("author_name") or n.get("author")
        if not author_raw:
            author = "(unknown)"
        elif isinstance(author_raw, int) or (
            isinstance(author_raw, str) and author_raw.isdigit()
        ):
            author = f"user#{author_raw}"
        else:
            author = str(author_raw)
        created = n.get("create_time") or n.get("modified_time") or "unknown"
        content = (n.get("content") or n.get("note") or "(empty)").strip()[:500]
        lines.append(f"  [{created}] {title} (by {author})")
        lines.append(f"    {content}")
        lines.append("")
    return "\n".join(lines)


def tool_list_playbooks(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """List available SOAR playbooks."""
    active_only = args.get("active_only", True)
    category = (args.get("category", "") or "").strip()

    params: dict = {"page_size": config.max_results}

    data, err = client.get("playbook", params=params)
    if err:
        return f"Error listing playbooks: {err}"

    items = data if isinstance(data, list) else data.get("data", [])
    total = data.get("count", len(items)) if isinstance(data, dict) else len(items)
    if active_only:
        items = [pb for pb in items if bool(pb.get("active"))]
    if category:
        cat = category.lower()
        items = [pb for pb in items if cat in str(pb.get("category", "")).lower()]
    if not items:
        return "No playbooks found."

    count_label = f"{len(items)} of {total}" if total > len(items) else str(len(items))
    lines = [f"Available playbooks ({count_label}):\n"]
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
    run_id, err_msg = _require_positive_int(args.get("run_id"), "run_id")
    if err_msg:
        return err_msg

    data, err = client.get(f"playbook_run/{run_id}")
    if err:
        return f"Error fetching playbook run {run_id}: {err}"
    if not isinstance(data, dict):
        return f"Unexpected response for run {run_id}."

    status = data.get("status", "unknown")

    # Bug #4: SOAR returns 'playbook' as a flat integer (the playbook ID), not a
    # nested dict.  The human-readable name is embedded in the 'message' JSON blob.
    pb_name = str(data.get("playbook_id", "unknown"))
    try:
        msg_obj = json.loads(data.get("message", "{}") or "{}")
        pb_name = msg_obj.get("playbook") or msg_obj.get("name") or pb_name
    except (json.JSONDecodeError, TypeError):
        pass

    # Bug #4: start time may be 'start_time' or absent; fall back gracefully
    started = (
        data.get("start_time")
        or data.get("create_time")
        or "unknown"
    )

    return (
        f"Playbook Run #{run_id}\n"
        f"  Playbook:    {pb_name}\n"
        f"  Status:      {status}\n"
        f"  Case:        #{data.get('container', data.get('container_id', 'unknown'))}\n"
        f"  Started:     {started}\n"
        f"  Finished:    {data.get('update_time', data.get('end_time', 'still running'))}\n"
        f"  Message:     {data.get('message', '(none)')}"
    )


def tool_list_action_runs(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """List action runs for a case."""
    case_id, err_msg = _require_positive_int(args.get("case_id"), "case_id")
    if err_msg:
        return err_msg
    limit = min(int(args.get("limit") or 20), config.max_results)

    data, err = client.get(
        "action_run",
        params={"_filter_container": case_id, "page_size": limit, "sort": "create_time", "order": "desc"},
    )
    if err:
        return f"Error listing action runs for case {case_id}: {err}"

    items = data if isinstance(data, list) else data.get("data", [])
    total = data.get("count", len(items)) if isinstance(data, dict) else len(items)
    if not items:
        return f"No action runs found for case #{case_id}."

    count_label = f"{len(items)} of {total}" if total > len(items) else str(len(items))
    lines = [f"Action runs for case #{case_id} ({count_label} shown):\n"]
    for ar in items:
        # Bug #5: SOAR returns 'app' as a flat integer (app ID) not a nested dict.
        # Try 'app_name' first, then handle dict/string/int gracefully.
        app_field = ar.get("app")
        if isinstance(app_field, dict):
            app_name = app_field.get("name", "unknown")
        elif isinstance(app_field, str) and app_field:
            app_name = app_field
        else:
            app_name = ar.get("app_name") or (
                f"app#{app_field}" if isinstance(app_field, int) else "unknown"
            )
        lines.append(
            f"  [{ar.get('create_time', 'unknown')}] {ar.get('action', 'unknown')} "
            f"— {app_name} "
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
    total = data.get("count", len(items)) if isinstance(data, dict) else len(items)
    if not items:
        return "No users found."

    count_label = f"{len(items)} of {total}" if total > len(items) else str(len(items))
    lines = [f"SOAR Users ({count_label}):\n"]
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

    # Fetch extended system info (requires admin token; gracefully ignore 403)
    license_line = ""
    sys_data, _ = client.get("system_info")
    if isinstance(sys_data, dict):
        license_status = sys_data.get("license_status", "")
        license_type = sys_data.get("license_type", "")
        if license_status:
            license_line = f"\n  License:  {license_status}" + (f" ({license_type})" if license_type else "")

    # Bug #2: endpoint URL was hardcoded with the wrong handler dir and asset name.
    # Read the persisted endpoint from config (written by the connector on first connect).
    mcp_ep = config.mcp_endpoint or f"{client._base_url}/rest/handler/<soarmcpserver_appid>/<asset_name>"

    return (
        f"Splunk SOAR Instance\n"
        f"  Version:  {version} (build {build}){license_line}\n"
        f"  Apps installed: {app_count}\n"
        f"  REST API: {client._base_url}/rest\n"
        f"  MCP Endpoint: {mcp_ep}"
    )


# ── Write tools ────────────────────────────────────────────────────────────────

def tool_add_case_note(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """Add a note to a case."""
    case_id, err_msg = _require_positive_int(args.get("case_id"), "case_id")
    if err_msg:
        return err_msg

    note_text = (args.get("note") or "").strip()
    if not note_text:
        return "Error: note text is required."

    # Security fix #10: strip HTML tags to prevent stored XSS when the note is
    # rendered in the SOAR web UI (the CSP contains 'unsafe-inline' which would
    # allow injected <script> tags to execute in an analyst's browser).
    note_text = _HTML_TAG_RE.sub("", note_text)

    # Security fix #11: enforce a maximum note length to prevent storage exhaustion.
    if len(note_text) > _MAX_NOTE_LENGTH:
        return (
            f"Error: note exceeds maximum allowed length of {_MAX_NOTE_LENGTH} characters "
            f"({len(note_text)} chars supplied). Please shorten the note."
        )

    body = {
        "container_id": case_id,
        "content": note_text,
        "note_type": "general",
        "note_format": "markdown",
        "phase_id": 0,
        # Strip HTML from the title too (issue #42) — it is rendered in the UI.
        "title": _HTML_TAG_RE.sub("", (args.get("title") or "AI-Assisted Analysis Note").strip()),
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
    case_id, err_msg = _require_positive_int(args.get("case_id"), "case_id")
    if err_msg:
        return err_msg
    playbook_id, err_msg = _require_positive_int(args.get("playbook_id"), "playbook_id")
    if err_msg:
        return err_msg

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
    case_id, err_msg = _require_positive_int(args.get("case_id"), "case_id")
    if err_msg:
        return err_msg
    status = (args.get("status") or "").lower()
    if not status:
        return "Error: status is required."
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
    case_id, err_msg = _require_positive_int(args.get("case_id"), "case_id")
    if err_msg:
        return err_msg
    severity = (args.get("severity") or "").lower()
    if not severity:
        return "Error: severity is required."
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
    case_id, err_msg = _require_positive_int(args.get("case_id"), "case_id")
    if err_msg:
        return err_msg
    owner = (args.get("owner") or "").strip()
    if not owner:
        return "Error: owner is required."

    data, err = client.post(f"container/{case_id}", {"owner_name": owner})
    if err:
        return f"Error updating owner of case {case_id}: {err}"

    return f"✅ Case #{case_id} reassigned to '{owner}'." + (
        _disclaimer() if config.advisory_disclaimer else ""
    )


def tool_create_artifact(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """Create a new artifact on a case."""
    case_id, err_msg = _require_positive_int(args.get("case_id"), "case_id")
    if err_msg:
        return err_msg
    name = (args.get("name") or "").strip()
    art_type = (args.get("artifact_type") or "").strip()
    cef_data = args.get("cef_data") or {}
    if not name or not art_type:
        return "Error: name and artifact_type are required."
    if not isinstance(cef_data, dict):
        cef_data = {}

    # Security (issue #42): strip HTML from all client-controlled fields that are
    # rendered in the SOAR web UI. SOAR's CSP contains 'unsafe-inline', so an
    # injected <script>/<img onerror> in an artifact name or CEF value would
    # execute in an analyst's browser (stored XSS) — same hardening as add_case_note.
    name = _HTML_TAG_RE.sub("", name)
    art_type = _HTML_TAG_RE.sub("", art_type)
    label = _HTML_TAG_RE.sub("", str(args.get("label", "artifact")))
    cef_data = {
        _HTML_TAG_RE.sub("", str(k)): (_HTML_TAG_RE.sub("", v) if isinstance(v, str) else v)
        for k, v in cef_data.items()
    }

    body = {
        "container_id": case_id,
        "name": name,
        "label": label,
        "type": art_type,
        "cef": cef_data,
        "source_data_identifier": f"mcp_created_{name}",
        "run_automation": bool(args.get("run_automation", False)),
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
# Playbook-Discovery & Build tool implementations (v1.6.0+)
# ==============================================================================


def tool_create_container(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """Create an isolated test container for playbook self-testing."""
    # Double gate: tool enable flag (from asset config) AND safety flag in mcp.conf
    if not getattr(config, "enable_test_harness", False):
        return (
            "Error: create_container requires the test harness to be enabled. "
            "Enable it via the 'enable_test_harness' checkbox in the asset "
            "configuration (Apps → SOAR MCP Server → Asset Settings) and run "
            "Test Connectivity — no SSH needed. (Equivalent to enable_test_harness "
            "= true in the [safety] section of mcp.conf.) This prevents accidental "
            "case creation on production SOAR instances; enable only on test/dev."
        )

    name = (args.get("name") or "").strip()
    if not name:
        return "Error: name is required."

    label = (args.get("label") or "test").strip()
    severity = (args.get("severity") or "low").strip().lower()
    if severity not in _VALID_SEVERITIES:
        severity = "low"

    body = {
        "name": name,
        "label": label,
        "severity": severity,
        "status": "new",
    }

    data, err = client.post("container", body)
    if err:
        return f"Error creating container: {err}"

    if not isinstance(data, dict):
        return f"Container create response (raw): {data}"

    # VERIFY: response field 'id' on SOAR 8.5 (standard REST create response)
    container_id = data.get("id") or data.get("container_id") or "unknown"
    failed = data.get("failed", False)
    if failed:
        return f"Error: SOAR reported failed=true. Response: {data}"

    return (
        f"✅ Test container created.\n"
        f"  Container ID: {container_id}\n"
        f"  Name: {name}\n"
        f"  Label: {label} | Severity: {severity}"
    ) + (_disclaimer() if config.advisory_disclaimer else "")


def tool_delete_container(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """Delete a test container — closes the create→test→cleanup loop (issue #66)."""
    # Same double gate as create_container: never allow deletion unless the test
    # harness is explicitly enabled, so real production cases can't be removed.
    if not getattr(config, "enable_test_harness", False):
        return (
            "Error: delete_container requires the test harness to be enabled. "
            "Enable it via the 'enable_test_harness' checkbox in the asset "
            "configuration (Apps → SOAR MCP Server → Asset Settings) and run "
            "Test Connectivity. Never enable on a production SOAR instance."
        )

    container_id, err_msg = _require_positive_int(args.get("container_id"), "container_id")
    if err_msg:
        return err_msg

    # Safety: refuse to delete a container that is not a recognisable test
    # container unless the caller explicitly forces it. create_container writes
    # a "test" label by default; require confirm=true to delete anything else.
    confirm = bool(args.get("confirm", False))
    existing, _ = client.get(f"container/{container_id}")
    if isinstance(existing, dict):
        label = (existing.get("label") or "").lower()
        if label != "test" and not confirm:
            return (
                f"Refusing to delete container #{container_id}: its label is "
                f"'{existing.get('label') or 'none'}', not 'test'. This does not look "
                "like an MCP test container. Re-call with confirm=true if you are sure."
            )

    data, err = client.delete(f"container/{container_id}")
    if err:
        return f"Error deleting container {container_id}: {err}"

    return (
        f"✅ Test container #{container_id} deleted."
    ) + (_disclaimer() if config.advisory_disclaimer else "")


def tool_import_playbook(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """Import a playbook archive into SOAR (POST /rest/import_playbook, JSON body)."""
    import base64 as _b64

    # Strip ALL whitespace (incl. internal newlines MCP transport may inject)
    archive_b64 = "".join((args.get("archive_b64") or "").split())
    if not archive_b64:
        return "Error: archive_b64 is required."

    try:
        raw_bytes = _b64.b64decode(archive_b64, validate=True)
    except Exception:
        return "Error: archive_b64 is not valid base64."

    scm_arg = (args.get("scm") or "local").strip()
    force = bool(args.get("force", False))

    # Resolve writable SCM to an integer id.
    # Issue #32: field name is scm_id (int), not scm (str).
    # GET /rest/scm returns "community" (id=1) as first result — skip it (read-only).
    resolved_scm_id: Optional[int] = None
    scm_name_resolved: str = ""

    if scm_arg.lower() in ("local", ""):
        scm_list, _ = client.get("scm")
        candidates: list = []
        if isinstance(scm_list, list):
            candidates = scm_list
        elif isinstance(scm_list, dict):
            candidates = scm_list.get("data") or []
        for s in candidates:
            if not isinstance(s, dict):
                continue
            if s.get("read_only") or s.get("is_read_only") or s.get("readonly"):
                continue
            repo_name = (s.get("name") or "").lower()
            if repo_name in ("community", "splunk-soar-community"):
                continue
            if s.get("type", "").lower() in ("local", "git"):
                try:
                    resolved_scm_id = int(s["id"])
                    scm_name_resolved = s.get("name") or str(resolved_scm_id)
                except (KeyError, TypeError, ValueError):
                    pass
                break
    else:
        # Caller passed an explicit id or name
        try:
            resolved_scm_id = int(scm_arg)
            scm_name_resolved = scm_arg
        except ValueError:
            # string name — pass as-is in scm field (fallback)
            scm_name_resolved = scm_arg

    # SOAR REST reference: POST /rest/import_playbook
    # Body: { "playbook": "<base64 gzip TAR>", "scm_id": <int>, "force": <bool> }
    # Field name is scm_id (integer), NOT scm (string) — that was the original 400 cause.
    body: dict = {
        "playbook": archive_b64,
        "force": force,
    }
    if resolved_scm_id is not None:
        body["scm_id"] = resolved_scm_id
    elif scm_name_resolved:
        body["scm"] = scm_name_resolved  # fallback: string name

    data, err = client.post("import_playbook", body)

    if err:
        if "403" in str(err):
            return (
                f"Error importing playbook: {err}\n\n"
                f"Diagnostics: scm_arg={scm_arg!r}, resolved_scm_id={resolved_scm_id!r} "
                f"({scm_name_resolved!r})\n"
                "Possible causes:\n"
                "  1. SCM repo is still read-only — pass an explicit writable scm=<id>.\n"
                "  2. Token user lacks write permission — check Administration → Audit.\n"
                "  3. 'Automation Engineer' role may be required in addition to Administrator."
            )
        if "400" in str(err):
            return (
                f"Error importing playbook (HTTP 400): {err}\n\n"
                f"Diagnostics: scm_arg={scm_arg!r}, resolved_scm_id={resolved_scm_id!r}, "
                f"archive={len(raw_bytes):,} bytes\n"
                "Possible causes:\n"
                "  1. scm_id not found — pass explicit scm=<id> from GET /rest/scm.\n"
                "  2. Archive corrupt — verify archive_b64 is from export_playbook.\n"
                "  3. Duplicate name + force=False — retry with force=True."
            )
        return f"Error importing playbook: {err}"

    if not isinstance(data, dict):
        return f"Import response (raw): {data}"

    pb_id = data.get("playbook_id") or data.get("id") or "unknown"
    name = data.get("playbook") or data.get("name") or "unknown"
    status = data.get("status") or data.get("message") or "imported"

    return (
        f"✅ Playbook imported successfully.\n"
        f"  Name: {name}\n"
        f"  ID: {pb_id}\n"
        f"  Status: {status}\n"
        f"  SCM: {scm_name_resolved or resolved_scm_id or 'default'}"
    ) + (_disclaimer() if config.advisory_disclaimer else "")


def tool_export_playbook(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """Export a playbook as a base64-encoded gzip TAR archive."""
    import base64 as _b64

    pb_id, err_msg = _require_positive_int(args.get("playbook_id"), "playbook_id")
    if err_msg:
        return err_msg

    # VERIFY: GET /rest/playbook/{id}/export returns x-gzip binary on SOAR 8.5
    # (confirmed in SOAR REST reference for 8.x and Appendix A of the instruction)
    content, err = client.get_binary(f"playbook/{pb_id}/export")
    if err:
        return f"Error exporting playbook {pb_id}: {err}"

    if not content:
        return f"Error: empty response for playbook {pb_id} export."

    encoded = _b64.b64encode(content).decode("ascii")
    return (
        f"Playbook #{pb_id} exported ({len(content):,} bytes).\n"
        f"archive_b64: {encoded}"
    )


def tool_get_action_schema(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """Return input parameters and output datapaths for actions of a SOAR app."""
    app_id_raw = args.get("app_id")
    action_filter = (args.get("action_name") or "").strip().lower()

    if not app_id_raw and not action_filter:
        return "Error: at least one of app_id or action_name is required."

    app_name_hint = ""

    # If only action_name given, find the app via the /rest/app list
    if not app_id_raw and action_filter:
        all_data, _ = client.get("app", params={"page_size": 0})
        if isinstance(all_data, dict):
            for a in (all_data.get("data") or []):
                searchable = " ".join([
                    a.get("name") or "",
                    a.get("product_name") or "",
                    a.get("product_vendor") or "",
                ]).lower()
                if action_filter in searchable:
                    app_id_raw = a.get("id")
                    app_name_hint = a.get("name", "")
                    break
        if not app_id_raw:
            return (
                f"No app found matching '{action_filter}'. "
                f"Try list_apps to browse installed connectors, then call with app_id."
            )

    app_id, err_msg = _require_positive_int(app_id_raw, "app_id")
    if err_msg:
        return err_msg

    # Fetch the app name for display (lightweight call)
    if not app_name_hint:
        meta, _ = client.get(f"app/{app_id}")
        if isinstance(meta, dict):
            app_name_hint = meta.get("name", f"app_{app_id}")
        else:
            app_name_hint = f"app_{app_id}"

    # Action definitions live at /rest/app_action, not inside the app record.
    # The app record (/rest/app/{id}) only contains metadata (config, directory, etc.)
    data, err = client.get("app_action", params={"_filter_app": app_id, "page_size": 0})
    if err:
        return f"Error fetching actions for app {app_id} ({app_name_hint}): {err}"
    if not isinstance(data, dict):
        return f"Error: unexpected response type fetching actions for app {app_id}"

    actions = data.get("data") or []
    if not actions:
        return (
            f"App {app_id} ({app_name_hint}): no actions found at "
            f"/rest/app_action?_filter_app={app_id} (total count={data.get('count', 0)})."
        )

    if action_filter:
        actions = [
            a for a in actions
            if action_filter in (a.get("action") or "").lower()
            or action_filter in (a.get("identifier") or "").lower()
            or action_filter in (a.get("name") or "").lower()
        ]
    if not actions:
        return f"No action matching '{action_filter}' found in app {app_id} ({app_name_hint})."

    lines = [f"Action Schema — {app_name_hint} (app_id={app_id}):"]

    for action in actions[:20]:
        label = action.get("action") or action.get("name") or action.get("identifier") or "?"
        a_type = action.get("type", "unknown")
        read_only = action.get("read_only", "?")
        lines.append(f"\n  ── {label} (type={a_type}, read_only={read_only}) ──")

        # parameters: dict {name: {data_type, required, contains}} or list [{name, ...}]
        params_raw = action.get("parameters") or {}
        if isinstance(params_raw, dict):
            if params_raw:
                lines.append("    Parameters:")
                for p_name, p_info in params_raw.items():
                    if not isinstance(p_info, dict):
                        continue
                    req = "required" if p_info.get("required") else "optional"
                    dtype = p_info.get("data_type", "string")
                    contains = p_info.get("contains") or []
                    c_str = f"  [contains: {', '.join(contains)}]" if contains else ""
                    lines.append(f"      {p_name} ({dtype}, {req}){c_str}")
            else:
                lines.append("    Parameters: (none)")
        elif isinstance(params_raw, list):
            lines.append("    Parameters:")
            for p in params_raw:
                p_name = p.get("name") or p.get("data_item_name") or "?"
                req = "required" if p.get("required") else "optional"
                dtype = p.get("data_type", "string")
                contains = p.get("contains") or []
                c_str = f"  [contains: {', '.join(contains)}]" if contains else ""
                lines.append(f"      {p_name} ({dtype}, {req}){c_str}")

        outputs = action.get("output") or []
        if outputs:
            lines.append("    Output datapaths:")
            for o in outputs[:20]:
                dp = o.get("data_path", "?")
                dtype = o.get("data_type", "?")
                contains = o.get("contains") or []
                c_str = f"  [contains: {', '.join(contains)}]" if contains else ""
                lines.append(f"      {dp} ({dtype}){c_str}")
        else:
            lines.append("    Output datapaths: (none)")

    return "\n".join(lines)


def tool_list_assets(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """List configured SOAR assets (connector instances)."""
    app_id_raw = args.get("app_id")
    limit = min(int(args.get("limit") or config.max_results), config.max_results)

    params: dict = {"page_size": 0}
    if app_id_raw is not None:
        app_id_val, err_msg = _require_positive_int(app_id_raw, "app_id")
        if err_msg:
            return err_msg
        # VERIFY: filter param name on SOAR 8.5 (_filter_app vs _filter_app_id)
        params["_filter_app"] = app_id_val

    data, err = client.get("asset", params=params)
    if err:
        return f"Error listing assets: {err}"

    assets = data.get("data", []) if isinstance(data, dict) else []
    total = data.get("count", len(assets)) if isinstance(data, dict) else len(assets)
    assets = assets[:limit]

    if not assets:
        return f"No assets found{' for app_id=' + str(app_id_raw) if app_id_raw else ''}."

    lines = [f"Configured SOAR Assets ({len(assets)} shown, {total} total):"]
    for a in assets:
        # VERIFY: 'app' field on 8.5 — may be int (app_id) or nested dict
        app_val = a.get("app")
        if isinstance(app_val, int):
            app_id_str = str(app_val)
        elif isinstance(app_val, dict):
            app_id_str = str(app_val.get("id", "?"))
        else:
            app_id_str = str(app_val) if app_val is not None else "unknown"

        # VERIFY: 'configuration_status' vs 'configured' boolean on 8.5
        cfg_status = a.get("configuration_status") or (
            "configured" if a.get("configured") else "not configured"
        )
        lines.append(
            f"\n  ID: {a.get('id')} | {a.get('name', '(unnamed)')}\n"
            f"    App ID: {app_id_str} | Product: {a.get('product_name', 'unknown')}\n"
            f"    Status: {cfg_status}"
        )
    return "\n".join(lines)


def tool_list_apps(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """List installed SOAR apps/connectors."""
    name_filter = (args.get("name_contains") or "").strip().lower()
    limit = min(int(args.get("limit") or config.max_results), config.max_results)

    data, err = client.get("app", params={"page_size": 0})
    if err:
        return f"Error listing apps: {err}"

    # VERIFY: 'data' array field name on SOAR 8.5 (expected from REST reference)
    apps = data.get("data", []) if isinstance(data, dict) else []
    total = data.get("count", len(apps)) if isinstance(data, dict) else len(apps)

    if name_filter:
        apps = [
            a for a in apps
            if name_filter in (a.get("name") or "").lower()
            or name_filter in (a.get("product_name") or "").lower()
        ]

    apps = apps[:limit]
    if not apps:
        return f"No apps found{' matching ' + repr(name_filter) if name_filter else ''}."

    lines = [f"Installed SOAR Apps ({len(apps)} shown, {total} total):"]
    for a in apps:
        # VERIFY: 'supported_actions' field name on SOAR 8.5
        supported = a.get("supported_actions") or []
        actions_str = (
            f"{len(supported)} action(s): {', '.join(supported[:5])}"
            + (" …" if len(supported) > 5 else "")
            if supported else "actions unknown (call get_action_schema)"
        )
        lines.append(
            f"\n  ID: {a.get('id')} | {a.get('name', '(unnamed)')}\n"
            f"    Vendor: {a.get('product_vendor') or a.get('publisher') or 'unknown'} | "
            f"Product: {a.get('product_name', 'unknown')}\n"
            f"    {actions_str}"
        )
    return "\n".join(lines)


# ==============================================================================
# COA Visual Editor tool implementations (v1.6.3+)
# ==============================================================================

from soar_mcp_utils import redact_nested  # noqa: E402 — after stdlib imports


# ── Shared COA helpers ─────────────────────────────────────────────────────────

def _resolve_current_id(
    client: SoarApiClient, pid: int
) -> tuple[int, dict, str | None]:
    """
    Resolve *pid* to the current Visual Editor draft.

    Returns (current_id, coa_data_dict, error_or_None).
    Tries COA first, falls back to /rest/playbook/{pid} if COA is unreachable.
    """
    coa_data, err = client._coa_get(f"playbooks/{pid}")
    if err or not isinstance(coa_data, dict):
        # COA unavailable — try REST fallback
        rest_data, rest_err = client.get(f"playbook/{pid}")
        if rest_err or not isinstance(rest_data, dict):
            return pid, {}, f"COA error: {err}; REST fallback error: {rest_err}"
        # VERIFY: field name for current draft ID in /rest/playbook/{id} response
        current_id = rest_data.get("current_id") or rest_data.get("id") or pid
        return int(current_id), {}, None

    # Live SOAR 8.5: current_id may be at top level, inside "coa", or inside "coa.data"
    coa_sub = coa_data.get("coa") or {}
    data_sub = coa_sub.get("data") or {}
    raw_current = (
        coa_data.get("current_id")
        or data_sub.get("current_id")
        or coa_sub.get("current_id")
        or coa_data.get("id")
        or pid
    )
    current_id = int(raw_current)

    # SOAR 8.5 can return current_id while still returning the old revision's
    # graph for /coa/playbooks/<old_id>. Refetch the current draft payload before
    # any COA graph analysis so stale URLs do not poison downstream checks.
    if current_id != pid:
        current_data, current_err = client._coa_get(f"playbooks/{current_id}")
        if not current_err and isinstance(current_data, dict):
            return current_id, current_data, None

    return current_id, coa_data, None


def _get_coa_nodes_edges(coa_data: dict) -> tuple[list, list]:
    """
    Extract nodes and edges from a COA graph response.

    Known shapes:
      A) export archive JSON:   coa_data["coa"]["data"]["nodes"]
      B) live /coa/playbooks/{id} on SOAR 8.5 (no outer "coa" wrapper):
                                coa_data["data"]["nodes"]
      C) flat top-level:        coa_data["nodes"]
      D) older SOAR 8.5 hotfix shape:
                                coa_data["coa_data"]["nodes"]

    Nodes may be a dict keyed by string node-id — normalised to list.
    Edges field may be "connections" or "edges".
    """
    coa_sub = coa_data.get("coa") or {}
    coa_data_sub = coa_data.get("coa_data") or {}
    if isinstance(coa_data_sub, str):
        try:
            coa_data_sub = json.loads(coa_data_sub)
        except Exception:
            coa_data_sub = {}
    if not isinstance(coa_data_sub, dict):
        coa_data_sub = {}

    # data_sub: prefer shape A (coa.data), then B (top-level data), then D.
    data_sub = coa_sub.get("data") or coa_data.get("data") or coa_data_sub or {}

    nodes_raw = (
        data_sub.get("nodes")        # shapes A and B
        or coa_data_sub.get("nodes") # shape D
        or coa_sub.get("nodes")      # coa.nodes (uncommon fallback)
        or coa_data.get("nodes")     # shape C
        or {}
    )
    if isinstance(nodes_raw, dict):
        nodes: list = list(nodes_raw.values())
    elif isinstance(nodes_raw, list):
        nodes = nodes_raw
    else:
        nodes = []

    edges_raw = (
        data_sub.get("connections") or data_sub.get("edges")
        or coa_data_sub.get("connections") or coa_data_sub.get("edges")
        or coa_sub.get("connections") or coa_sub.get("edges")
        or coa_data.get("connections") or coa_data.get("edges")
        or coa_data.get("links")
        or []
    )
    edges: list = edges_raw if isinstance(edges_raw, list) else []

    def _issue_list(value: Any) -> list:
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            return [v for v in value.values() if v]
        return []

    normalized_nodes: list[dict] = []
    node_name_by_id: dict[str, str] = {}
    for raw in nodes:
        if not isinstance(raw, dict):
            continue
        data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
        rec = dict(data) if data else dict(raw)

        node_id = raw.get("id", rec.get("id"))
        if node_id is not None:
            rec["id"] = node_id
            rec["node_id"] = node_id
        rec["x"] = raw.get("x", rec.get("x", 0))
        rec["y"] = raw.get("y", rec.get("y", 0))
        rec["warnings"] = _issue_list(raw.get("warnings", rec.get("warnings", [])))
        rec["errors"] = _issue_list(raw.get("errors", rec.get("errors", [])))
        if "userCode" in raw and "userCode" not in rec:
            rec["userCode"] = raw.get("userCode")

        fn_name = rec.get("functionName") or rec.get("function_name") or rec.get("name") or ""
        if node_id is not None:
            node_name_by_id[str(node_id)] = str(fn_name)
        normalized_nodes.append(rec)

    normalized_edges: list[dict] = []
    for raw in edges:
        if not isinstance(raw, dict):
            continue
        rec = dict(raw)
        src_id = rec.get("source") or rec.get("source_id") or rec.get("from") or rec.get("sourceNode")
        tgt_id = rec.get("target") or rec.get("target_id") or rec.get("to") or rec.get("targetNode")
        if src_id is not None:
            rec["source"] = src_id
            rec.setdefault("source_function", node_name_by_id.get(str(src_id), str(src_id)))
        if tgt_id is not None:
            rec["target"] = tgt_id
            rec.setdefault("target_function", node_name_by_id.get(str(tgt_id), str(tgt_id)))
        normalized_edges.append(rec)

    return normalized_nodes, normalized_edges


def _coa_shape_debug(coa_data: dict) -> dict:
    """Return top-level and data-sub keys for diagnostics when node_count==0."""
    top_keys = list(coa_data.keys()) if isinstance(coa_data, dict) else []
    data_sub = (coa_data.get("coa") or {}).get("data") or coa_data.get("data") or {}
    return {
        "coa_top_keys": top_keys,
        "coa_data_sub_keys": list(data_sub.keys()),
        "note": "node_count=0: paste these keys in issue #30 to identify correct path",
    }


def _get_graph_from_export(client: "SoarApiClient", playbook_id: int) -> tuple[list, list]:
    """
    Extract COA nodes + edges from the export archive.

    SOAR 8.5: GET /coa/playbooks/{id} returns only the envelope
    (inputSpec, outputSpec, python, metadata) — the node/edge graph is
    absent even for VPE-native playbooks.  The export archive always
    contains the full graph at coa.data.nodes (dict) + coa.data.edges (list).

    Archive structure (confirmed via issue #30 retest):
        <name>.json → { "coa": { "data": { "nodes": {...}, "edges": [...] } } }
    """
    import io as _io_g
    import json as _json_g
    import tarfile as _tarfile_g

    content, _ = client.get_binary(f"playbook/{playbook_id}/export")
    if not content:
        return [], []
    try:
        buf = _io_g.BytesIO(content)
        with _tarfile_g.open(fileobj=buf, mode="r:*") as tarf:
            for member in tarf.getmembers():
                if not member.name.endswith(".json"):
                    continue
                fobj = tarf.extractfile(member)
                if not fobj:
                    continue
                raw = fobj.read()
                try:
                    doc = _json_g.loads(raw.decode("utf-8"))
                except Exception:
                    continue
                coa_sub = doc.get("coa") or {}
                data_sub = coa_sub.get("data") or {}
                nodes_raw = data_sub.get("nodes") or {}
                if not nodes_raw:
                    continue  # try next JSON file in archive
                nodes = list(nodes_raw.values()) if isinstance(nodes_raw, dict) else (
                    nodes_raw if isinstance(nodes_raw, list) else []
                )
                edges_raw = data_sub.get("edges") or data_sub.get("connections") or []
                edges = edges_raw if isinstance(edges_raw, list) else []
                return nodes, edges
    except Exception:
        pass
    return [], []


def _get_graph(
    client: "SoarApiClient", playbook_id: int, coa_data: dict
) -> tuple[list, list]:
    """
    Return (nodes, edges) for a playbook.

    Tries the live COA response first; falls back to the export archive
    when the live endpoint returns an empty graph (SOAR 8.5 behaviour —
    issue #30 third-pass fix).
    """
    nodes, edges = _get_coa_nodes_edges(coa_data)
    if not nodes:
        nodes, edges = _get_graph_from_export(client, playbook_id)
    return nodes, edges


def _extract_python_from_export(client: "SoarApiClient", playbook_id: int) -> Optional[str]:
    """Return the generated .py payload from a playbook export archive."""
    import io as _io_py
    import tarfile as _tarfile_py

    content, _ = client.get_binary(f"playbook/{playbook_id}/export")
    if not content:
        return None
    try:
        buf = _io_py.BytesIO(content)
        with _tarfile_py.open(fileobj=buf, mode="r:*") as tarf:
            for member in tarf.getmembers():
                if not member.name.endswith(".py"):
                    continue
                fobj = tarf.extractfile(member)
                if fobj:
                    return fobj.read().decode("utf-8", errors="replace")
    except Exception:
        return None
    return None


def _extract_python_from_coa(nodes: list) -> Optional[str]:
    """
    Reconstruct a Python payload from COA userCode blocks.

    SOAR 8.5 does not expose saved Python as a REST field; instead it regenerates
    Python from COA userCode on every VPE save. Combining all userCode blocks gives
    a functionally equivalent payload for compile/lint checks.

    # VERIFY: userCode field name inside a code node — may be "userCode", "user_code", or "code"
    """
    parts: list[str] = []
    for n in nodes:
        if (n.get("type") or "").lower() != "code":
            continue
        code = n.get("userCode") or n.get("user_code") or n.get("code") or ""
        if code.strip():
            fn_name = (
                n.get("functionName") or n.get("function_name") or n.get("name") or "block"
            )
            parts.append(f"# --- {fn_name} ---\n{textwrap.dedent(str(code)).strip()}")
    return "\n\n".join(parts) if parts else None


def _extract_python_from_coa_payload(coa_data: dict) -> Optional[str]:
    """Return full generated Python from known COA envelope fields, if present."""
    candidates: list[Any] = [
        coa_data.get("python"),
        coa_data.get("code"),
        (coa_data.get("coa") or {}).get("python") if isinstance(coa_data.get("coa"), dict) else None,
        (coa_data.get("coa") or {}).get("code") if isinstance(coa_data.get("coa"), dict) else None,
    ]
    data_sub = (coa_data.get("coa") or {}).get("data") if isinstance(coa_data.get("coa"), dict) else None
    if not data_sub and isinstance(coa_data.get("data"), dict):
        data_sub = coa_data.get("data")
    if isinstance(data_sub, dict):
        candidates.extend([data_sub.get("python"), data_sub.get("code")])
    for value in candidates:
        if isinstance(value, str) and value.strip():
            return value
    return None


def _select_playbook_python(
    client: "SoarApiClient",
    current_id: int,
    coa_data: dict,
    rest_data: dict | None,
    nodes: list,
) -> tuple[Optional[str], Optional[str]]:
    """
    Return the best full Python payload for validation/drift checks.

    Prefer full generated sources (REST/COA/export) over node snippets. Node
    snippets are a last resort because SOAR may store them indented relative to
    generated wrapper code, which can false-fail py_compile.
    """
    if isinstance(rest_data, dict):
        for key in ("code", "script", "playbook_run_data", "python"):
            value = rest_data.get(key)
            if isinstance(value, str) and value.strip():
                return value, f"rest_{key}"

    coa_python = _extract_python_from_coa_payload(coa_data)
    if coa_python:
        return coa_python, "coa_python"

    export_python = _extract_python_from_export(client, current_id)
    if export_python:
        return export_python, "export_archive"

    snippet_python = _extract_python_from_coa(nodes)
    if snippet_python:
        return snippet_python, "coa_usercode_snippets"

    return None, None


def _collect_coa_owned_function_names(nodes: list) -> set[str]:
    """Collect generated function names that are owned by the COA graph."""
    import ast as _ast_owned

    names: set[str] = {"on_start", "on_finish"}
    for n in nodes:
        if not isinstance(n, dict):
            continue
        fn_name = n.get("functionName") or n.get("function_name") or n.get("name")
        if fn_name:
            fn = str(fn_name)
            names.add(fn)
            names.add(f"{fn}_callback")
        code = n.get("userCode") or n.get("user_code") or n.get("code") or ""
        if code:
            try:
                tree = _ast_owned.parse(textwrap.dedent(str(code)))
                for node_obj in _ast_owned.walk(tree):
                    if isinstance(node_obj, _ast_owned.FunctionDef):
                        names.add(node_obj.name)
                        names.add(f"{node_obj.name}_callback")
            except SyntaxError:
                pass
    return names


def _normalize_coa_volatile(data: object, _depth: int = 0) -> object:
    """
    Deep-copy *data* with volatile fields stripped so two COA snapshots can be diffed.

    Volatile fields: hash, create_time, update_time, modified_time,
    create_datetime, update_datetime, utctime_updated.
    Does NOT strip id, x, y, or any functional field.
    """
    _VOLATILE = frozenset({
        "hash", "create_time", "update_time", "modified_time",
        "create_datetime", "update_datetime", "utctime_updated",
    })
    if _depth > 20:
        return data
    if isinstance(data, dict):
        return {
            k: _normalize_coa_volatile(v, _depth + 1)
            for k, v in data.items()
            if k not in _VOLATILE
        }
    if isinstance(data, list):
        return [_normalize_coa_volatile(item, _depth + 1) for item in data]
    return data


def _deep_diff(old: object, new: object, path: str = "") -> list[dict]:
    """Return a flat list of {path, old_val, new_val} for differing leaves."""
    diffs: list[dict] = []
    if isinstance(old, dict) and isinstance(new, dict):
        all_keys = set(old) | set(new)
        for k in sorted(all_keys):
            child_path = f"{path}.{k}" if path else k
            diffs.extend(_deep_diff(old.get(k), new.get(k), child_path))
    elif isinstance(old, list) and isinstance(new, list):
        for i, (o, n) in enumerate(zip(old, new)):
            diffs.extend(_deep_diff(o, n, f"{path}[{i}]"))
        if len(old) != len(new):
            diffs.append({"path": path, "old_len": len(old), "new_len": len(new)})
    else:
        if old != new:
            diffs.append({"path": path, "old": old, "new": new})
    return diffs


def _categorize_diff_path(path: str) -> str:
    """Map a diff path to a change category."""
    lower = path.lower()
    if any(k in lower for k in ("left", "top", "x", "y", ".x.", ".y.", "[x]", "[y]")):
        return "layout"
    if "usercode" in lower or "user_code" in lower:
        return "code_usercode"
    if "param" in lower:
        return "parameter"
    if any(k in lower for k in ("passed_validation", "draft_mode", "active")):
        return "validation_relevant"
    if any(k in lower for k in ("node", "connection", "edge", "block", "function")):
        return "graph_structure"
    if any(k in lower for k in ("name", "description", "label", "type", "trigger", "version")):
        return "metadata"
    return "wrapper"


# ── #17 resolve_playbook_current_id ───────────────────────────────────────────

def tool_resolve_playbook_current_id(
    client: SoarApiClient, config: McpServerConfig, args: dict
) -> str:
    pid, err_msg = _require_positive_int(args.get("playbook_id"), "playbook_id")
    if err_msg:
        return err_msg

    current_id, coa_data, err = _resolve_current_id(client, pid)

    findings = []
    errors = []
    if err:
        errors.append({"source": "coa", "message": err})

    is_current = (current_id == pid)
    if not is_current:
        findings.append({
            "severity": "warn",
            "code": "stale_id",
            "message": f"Input ID {pid} is a previous revision; use current_id {current_id} for further work.",
        })

    # VERIFY: field names in COA response — name, version, previous_versions, active, draft_mode, passed_validation
    name = coa_data.get("name", "")
    version = coa_data.get("version")
    previous_versions = coa_data.get("previous_versions") or []
    active = coa_data.get("active", False)
    draft_mode = coa_data.get("draft_mode", False)
    passed_validation = coa_data.get("passed_validation", False)
    lookup_source = "/coa/playbooks/" + str(pid) if not err else "rest_fallback"

    summary = (
        f"Input {pid} is already the current draft."
        if is_current
        else f"Input {pid} resolves to current draft {current_id}."
    )

    result = {
        "ok": len(errors) == 0,
        "summary": summary,
        "data": {
            "input_id": pid,
            "current_id": current_id,
            "is_current": is_current,
            "name": name,
            "version": version,
            "previous_versions": previous_versions,
            "active": active,
            "draft_mode": draft_mode,
            "passed_validation": passed_validation,
            "lookup_source": lookup_source,
        },
        "findings": findings,
        "errors": errors,
    }
    return json.dumps(result, indent=2)


# ── #18 get_playbook_identity_map ──────────────────────────────────────────────

def tool_get_playbook_identity_map(
    client: SoarApiClient, config: McpServerConfig, args: dict
) -> str:
    pb_name = (args.get("playbook") or "").strip()
    pb_id_raw = args.get("playbook_id")

    if not pb_name and pb_id_raw is None:
        return json.dumps({
            "ok": False,
            "summary": "Error: provide either playbook (name) or playbook_id.",
            "data": {}, "findings": [], "errors": [],
        }, indent=2)

    current_id: Optional[int] = None
    name_to_search = pb_name
    errors = []

    if pb_id_raw is not None:
        pid, err_msg = _require_positive_int(pb_id_raw, "playbook_id")
        if err_msg:
            return err_msg
        current_id, coa_data, err = _resolve_current_id(client, pid)
        if err:
            errors.append({"source": "coa", "message": err})
        if not name_to_search:
            # VERIFY: name field in COA or REST response
            name_to_search = coa_data.get("name", "")
            if not name_to_search:
                rest_data, _ = client.get(f"playbook/{pid}")
                if isinstance(rest_data, dict):
                    name_to_search = rest_data.get("name", "")

    # Query REST for all versions with this name
    params: dict = {"page_size": 0}
    if name_to_search:
        # VERIFY: exact-match filter name on /rest/playbook
        params["_filter_name__exact"] = f'"{name_to_search}"'

    data, err = client.get("playbook", params=params)
    if err:
        errors.append({"source": "rest", "message": err})
        return json.dumps({
            "ok": False, "summary": f"Error listing playbook versions: {err}",
            "data": {}, "findings": [], "errors": errors,
        }, indent=2)

    rows = data.get("data", []) if isinstance(data, dict) else []

    # If we only have an ID and no name, filter rows by matching ID or current_id
    if not name_to_search and current_id:
        rows = [r for r in rows if r.get("id") == current_id]

    versions = []
    found_current_id = current_id
    for r in rows:
        row_id = r.get("id")
        # VERIFY: version field name in /rest/playbook response
        ver_num = r.get("version") or r.get("version_number")
        row_current = r.get("current_id") or r.get("id")
        if found_current_id is None and row_current:
            found_current_id = int(row_current)
        versions.append({
            "id": row_id,
            "version": ver_num,
            "is_current": (row_id == found_current_id),
            "active": r.get("active", False),
            "draft_mode": r.get("draft_mode", False),
            "passed_validation": r.get("passed_validation", False),
        })

    # Sort by version then id
    versions.sort(key=lambda v: (v.get("version") or 0, v.get("id") or 0))

    n = len(versions)
    summary = f"Found {n} version(s)" + (
        f"; current draft is {found_current_id}." if found_current_id else "."
    )

    result = {
        "ok": len(errors) == 0,
        "summary": summary,
        "data": {
            "name": name_to_search,
            "current_id": found_current_id,
            "versions": versions,
        },
        "findings": [],
        "errors": errors,
    }
    return json.dumps(result, indent=2)


# ── #19 get_playbook_coa_summary ───────────────────────────────────────────────

def tool_get_playbook_coa_summary(
    client: SoarApiClient, config: McpServerConfig, args: dict
) -> str:
    pid, err_msg = _require_positive_int(args.get("playbook_id"), "playbook_id")
    if err_msg:
        return err_msg

    current_id, coa_data, err = _resolve_current_id(client, pid)
    errors = []
    if err:
        errors.append({"source": "coa", "message": err})

    # Fetch REST metadata for stable fields
    rest_data: dict = {}
    rest_val, rest_err = client.get(f"playbook/{current_id}")
    if isinstance(rest_val, dict):
        rest_data = rest_val
    elif rest_err:
        errors.append({"source": "rest", "message": rest_err})

    nodes, edges = _get_graph(client, current_id, coa_data)

    # VERIFY: customName field path inside node — may be node["advanced"]["customName"]
    custom_name_count = sum(
        1 for n in nodes
        if (n.get("advanced") or {}).get("customName") or n.get("customName")
    )
    # VERIFY: warnings / errors field inside node — may be list or count
    warning_count = sum(
        1 for n in nodes
        if isinstance(n.get("warnings"), list) and len(n["warnings"]) > 0
        or n.get("warning_count", 0) > 0
    )
    error_count = sum(
        1 for n in nodes
        if isinstance(n.get("errors"), list) and len(n["errors"]) > 0
        or n.get("error_count", 0) > 0
    )
    # VERIFY: inputSpec / outputSpec field names in COA top-level
    input_spec = coa_data.get("inputSpec") or coa_data.get("input_spec") or {}
    output_spec = coa_data.get("outputSpec") or coa_data.get("output_spec") or {}

    # Utility blocks: code/filter/decision nodes with functionId
    utility_blocks = [
        {
            "function_id": n.get("functionId") or n.get("function_id"),  # VERIFY
            "function_name": n.get("functionName") or n.get("function_name") or n.get("name"),  # VERIFY
            "type": n.get("type"),
        }
        for n in nodes
        if n.get("type") in ("code", "filter", "decision", "format", "prompt")
    ]

    # From REST metadata
    name = rest_data.get("name") or coa_data.get("name", "")
    version = rest_data.get("version") or coa_data.get("version")
    active = rest_data.get("active", coa_data.get("active", False))
    draft_mode = rest_data.get("draft_mode", coa_data.get("draft_mode", False))
    passed_validation = rest_data.get("passed_validation", coa_data.get("passed_validation", False))
    # VERIFY: playbook_type / trigger field names
    playbook_type = rest_data.get("playbook_type") or coa_data.get("playbook_type", "")
    trigger = (
        rest_data.get("playbook_trigger")
        or rest_data.get("trigger")
        or coa_data.get("playbook_trigger")
        or coa_data.get("trigger")
        or ""
    )

    findings = []
    if warning_count:
        findings.append({"severity": "warn", "code": "node_warnings",
                         "message": f"{warning_count} node(s) have stored warnings."})
    if error_count:
        findings.append({"severity": "high", "code": "node_errors",
                         "message": f"{error_count} node(s) have stored errors."})
    if not passed_validation:
        findings.append({"severity": "warn", "code": "validation_failed",
                         "message": "passed_validation is false on REST record."})

    data_block: dict = {
        "input_id": pid,
        "current_id": current_id,
        "is_current": (current_id == pid),
        "name": name,
        "version": version,
        "playbook_type": playbook_type,
        "trigger": trigger,
        "active": active,
        "draft_mode": draft_mode,
        "passed_validation": passed_validation,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "custom_name_count": custom_name_count,
        "warning_count": warning_count,
        "error_count": error_count,
        "input_spec": input_spec,
        "output_spec": output_spec,
        "utility_blocks": utility_blocks,
        "lookup_source": "/coa/playbooks/" + str(current_id) if not err else "rest_only",
    }

    # Diagnostic: surface raw COA response shape when node_count is 0 so
    # the caller can identify the correct traversal path (issue #30 follow-up).
    if len(nodes) == 0 and not err:
        data_block["_coa_shape_debug"] = _coa_shape_debug(coa_data)

    result = {
        "ok": len(errors) == 0,
        "summary": (
            f"Playbook '{name}' (id={current_id}): "
            f"{len(nodes)} nodes, {len(edges)} edges, "
            f"{warning_count} warnings, {error_count} errors."
        ),
        "data": data_block,
        "findings": findings,
        "errors": errors,
    }
    return json.dumps(result, indent=2)


# ── #20 list_playbook_nodes / list_playbook_edges ─────────────────────────────

def tool_list_playbook_nodes(
    client: SoarApiClient, config: McpServerConfig, args: dict
) -> str:
    pid, err_msg = _require_positive_int(args.get("playbook_id"), "playbook_id")
    if err_msg:
        return err_msg

    include_params = bool(args.get("include_parameters", False))
    type_filter = (args.get("type_filter") or "").lower().strip()
    name_contains = (args.get("function_name_contains") or "").lower().strip()

    current_id, coa_data, err = _resolve_current_id(client, pid)
    errors = []
    if err:
        errors.append({"source": "coa", "message": err})

    nodes, _ = _get_graph(client, current_id, coa_data)

    node_records = []
    for n in nodes:
        # VERIFY: field names for each attribute
        n_id = n.get("id") or n.get("node_id")
        fn_name = n.get("functionName") or n.get("function_name") or n.get("name") or ""
        n_type = (n.get("type") or "").lower()
        app = n.get("app") or n.get("app_name")
        action = n.get("action") or n.get("action_name")
        asset = n.get("asset") or n.get("asset_name")
        x = n.get("left") or n.get("x") or 0   # VERIFY: position key name
        y = n.get("top") or n.get("y") or 0     # VERIFY: position key name
        fn_id = n.get("functionId") or n.get("function_id")
        warnings = n.get("warnings") or []
        n_errors = n.get("errors") or []

        if type_filter and type_filter not in n_type:
            continue
        if name_contains and name_contains not in fn_name.lower():
            continue

        rec: dict = {
            "id": n_id,
            "function_name": fn_name,
            "type": n_type,
            "app": app,
            "action": action,
            "asset": asset,
            "x": x,
            "y": y,
            "function_id": fn_id,
            "warning_count": len(warnings) if isinstance(warnings, list) else 0,
            "error_count": len(n_errors) if isinstance(n_errors, list) else 0,
        }
        if include_params:
            raw_params = n.get("parameters") or n.get("params") or {}
            rec["parameters"] = redact_nested(raw_params)
        node_records.append(rec)

    # Sort by y, x, id
    node_records.sort(key=lambda r: (r.get("y") or 0, r.get("x") or 0, r.get("id") or 0))

    result = {
        "ok": True,
        "summary": f"{len(node_records)} node(s) in playbook {current_id}.",
        "data": {
            "input_id": pid,
            "current_id": current_id,
            "is_current": (current_id == pid),
            "total_nodes_in_coa": len(nodes),
            "filtered_nodes": len(node_records),
            "nodes": node_records,
        },
        "findings": [],
        "errors": errors,
    }
    return json.dumps(result, indent=2)


def tool_list_playbook_edges(
    client: SoarApiClient, config: McpServerConfig, args: dict
) -> str:
    pid, err_msg = _require_positive_int(args.get("playbook_id"), "playbook_id")
    if err_msg:
        return err_msg

    edge_from = (args.get("edge_from") or "").lower().strip()
    edge_to = (args.get("edge_to") or "").lower().strip()

    current_id, coa_data, err = _resolve_current_id(client, pid)
    errors = []
    if err:
        errors.append({"source": "coa", "message": err})

    _, edges = _get_graph(client, current_id, coa_data)

    edge_records = []
    for e in edges:
        # VERIFY: field names — source/target may be node IDs or function names
        e_id = e.get("id") or e.get("edge_id")
        src_id = e.get("source") or e.get("source_id") or e.get("from")
        tgt_id = e.get("target") or e.get("target_id") or e.get("to")
        src_fn = e.get("source_function") or e.get("sourceFunctionName") or str(src_id)
        tgt_fn = e.get("target_function") or e.get("targetFunctionName") or str(tgt_id)
        condition = e.get("condition") or e.get("label") or e.get("branch") or ""
        edge_type = e.get("type") or e.get("edge_type") or "normal"  # VERIFY

        if edge_from and edge_from not in (src_fn or "").lower():
            continue
        if edge_to and edge_to not in (tgt_fn or "").lower():
            continue

        edge_records.append({
            "id": e_id,
            "source_id": src_id,
            "source_function": src_fn,
            "target_id": tgt_id,
            "target_function": tgt_fn,
            "condition": condition,
            "edge_type": edge_type,
        })

    edge_records.sort(key=lambda r: (
        str(r.get("source_function") or ""),
        str(r.get("target_function") or ""),
        r.get("id") or 0,
    ))

    result = {
        "ok": True,
        "summary": f"{len(edge_records)} edge(s) in playbook {current_id}.",
        "data": {
            "input_id": pid,
            "current_id": current_id,
            "is_current": (current_id == pid),
            "total_edges_in_coa": len(edges),
            "filtered_edges": len(edge_records),
            "edges": edge_records,
        },
        "findings": [],
        "errors": errors,
    }
    return json.dumps(result, indent=2)


# ── #22 check_saved_generated_python_drift ────────────────────────────────────

def tool_check_saved_generated_python_drift(
    client: SoarApiClient, config: McpServerConfig, args: dict
) -> str:
    import ast as _ast

    pid, err_msg = _require_positive_int(args.get("playbook_id"), "playbook_id")
    if err_msg:
        return err_msg

    current_id, coa_data, err = _resolve_current_id(client, pid)
    errors = []
    if err:
        errors.append({"source": "coa", "message": err})

    nodes, _ = _get_graph(client, current_id, coa_data)
    coa_functions = _collect_coa_owned_function_names(nodes)

    rest_data, rest_err = client.get(f"playbook/{current_id}")
    if rest_err:
        errors.append({"source": "rest", "message": rest_err})
    saved_python, python_source = _select_playbook_python(
        client,
        current_id,
        coa_data,
        rest_data if isinstance(rest_data, dict) else {},
        nodes,
    )

    if not saved_python:
        result = {
            "ok": False,
            "summary": "Python payload not available from REST, COA, or export archive — check skipped.",
            "data": {
                "current_id": current_id,
                "drift_detected": False,
                "method": "static_usercode_analysis",
                "python_payload_available": False,
                "ast_parse_succeeded": False,
                "coa_defined_functions": sorted(coa_functions),
                "saved_python_functions": [],
                "external_helper_candidates": [],
                "status": "skipped",
                "skip_reason": "saved Python payload not found in REST, COA, or export archive",
            },
            "findings": [{
                "severity": "warn",
                "code": "python_payload_unavailable",
                "message": "Could not inspect generated Python; drift status is unknown.",
            }],
            "errors": errors,
        }
        return json.dumps(result, indent=2)

    # Parse saved Python
    saved_functions: set[str] = set()
    ast_ok = False
    try:
        tree = _ast.parse(saved_python)
        for node_obj in _ast.walk(tree):
            if isinstance(node_obj, _ast.FunctionDef):
                saved_functions.add(node_obj.name)
        ast_ok = True
    except SyntaxError as se:
        errors.append({"source": "ast_parse", "message": f"SyntaxError: {se}"})
        result = {
            "ok": False,
            "summary": "AST parse failed — drift check skipped.",
            "data": {
                "current_id": current_id,
                "drift_detected": False,
                "method": "fallback_unavailable",
                "python_payload_available": True,
                "python_source": python_source,
                "ast_parse_succeeded": False,
                "coa_defined_functions": sorted(coa_functions),
                "saved_python_functions": [],
                "external_helper_candidates": [],
                "status": "skipped",
                "skip_reason": str(se),
            },
            "findings": [],
            "errors": errors,
        }
        return json.dumps(result, indent=2)

    external_helpers = sorted(saved_functions - coa_functions)
    drift_detected = bool(external_helpers)

    findings = []
    for fn_name in external_helpers:
        findings.append({
            "severity": "warn",
            "code": "saved_generated_python_drift",
            "message": (
                f"Function '{fn_name}' exists in saved Python but is not defined in any COA "
                f"userCode block. It will be dropped when the Visual Editor next saves."
            ),
        })

    result = {
        "ok": not drift_detected,
        "summary": (
            f"Drift detected: {len(external_helpers)} external helper(s) at risk."
            if drift_detected else "No drift detected — all saved functions appear in COA userCode."
        ),
        "data": {
            "current_id": current_id,
            "drift_detected": drift_detected,
            "method": "static_usercode_analysis",
            "python_payload_available": True,
            "python_source": python_source,
            "ast_parse_succeeded": ast_ok,
            "coa_defined_functions": sorted(coa_functions),
            "saved_python_functions": sorted(saved_functions),
            "external_helper_candidates": external_helpers,
            "status": "completed",
        },
        "findings": findings,
        "errors": errors,
    }
    return json.dumps(result, indent=2)


# ── #23 check_datapath_selectability (Phase A — schema-only) ──────────────────

def _fetch_action_schema_raw(
    client: SoarApiClient, app_id: int, action_name: str
) -> tuple[list[dict], str | None]:
    """
    Fetch all action records for app_id and return those matching action_name.
    Reuses the /rest/app_action endpoint logic from tool_get_action_schema.
    """
    data, err = client.get("app_action", params={
        "_filter_app": app_id,
        "page_size": 0,
    })
    if err:
        return [], err
    actions = data.get("data", []) if isinstance(data, dict) else []
    if not isinstance(actions, list):
        return [], "Unexpected response shape from /rest/app_action"
    af = action_name.lower()
    matched = [
        a for a in actions
        if af in (a.get("action") or "").lower()
        or af in (a.get("identifier") or "").lower()
        or af in (a.get("name") or "").lower()
    ]
    return matched, None


def _extract_contains(outputs_or_params: list[dict], field_name: str = "") -> list[str]:
    """Collect unique 'contains' tag values from a list of output or parameter dicts."""
    tags: set[str] = set()
    for item in outputs_or_params:
        if not isinstance(item, dict):
            continue
        if field_name and (item.get("data_path") or item.get("name") or "").lower() != field_name.lower():
            continue
        for tag in (item.get("contains") or []):
            if tag:
                tags.add(str(tag))
    return sorted(tags)


def tool_check_datapath_selectability(
    client: SoarApiClient, config: McpServerConfig, args: dict
) -> str:
    prod_app_id, err = _require_positive_int(args.get("producer_app_id"), "producer_app_id")
    if err:
        return err
    cons_app_id, err = _require_positive_int(args.get("consumer_app_id"), "consumer_app_id")
    if err:
        return err
    prod_action = (args.get("producer_action") or "").strip()
    cons_action = (args.get("consumer_action") or "").strip()
    cons_param = (args.get("consumer_parameter") or "").strip()
    datapath = (args.get("datapath") or "").strip()

    if not prod_action or not cons_action or not cons_param:
        return json.dumps({
            "ok": False, "summary": "Error: producer_action, consumer_action, consumer_parameter are required.",
            "data": {}, "findings": [], "errors": [],
        }, indent=2)

    # Fetch producer schema
    prod_actions, err = _fetch_action_schema_raw(client, prod_app_id, prod_action)
    if err:
        return json.dumps({
            "ok": False, "summary": f"Error fetching producer schema: {err}",
            "data": {}, "findings": [], "errors": [{"source": "rest", "message": err}],
        }, indent=2)
    if not prod_actions:
        return json.dumps({
            "ok": False, "summary": f"Producer action '{prod_action}' not found for app {prod_app_id}.",
            "data": {}, "findings": [], "errors": [],
        }, indent=2)

    # Fetch consumer schema
    cons_actions, err = _fetch_action_schema_raw(client, cons_app_id, cons_action)
    if err:
        return json.dumps({
            "ok": False, "summary": f"Error fetching consumer schema: {err}",
            "data": {}, "findings": [], "errors": [{"source": "rest", "message": err}],
        }, indent=2)
    if not cons_actions:
        return json.dumps({
            "ok": False, "summary": f"Consumer action '{cons_action}' not found for app {cons_app_id}.",
            "data": {}, "findings": [], "errors": [],
        }, indent=2)

    # Extract contains tags
    prod_outputs = prod_actions[0].get("output") or []
    # Filter by datapath suffix if provided
    dp_part = datapath.split(".")[-1] if datapath else ""
    if dp_part and isinstance(prod_outputs, list):
        filtered = [o for o in prod_outputs if dp_part in (o.get("data_path") or "")]
        prod_contains = _extract_contains(filtered) if filtered else _extract_contains(prod_outputs)
    else:
        prod_contains = _extract_contains(prod_outputs)

    cons_params_raw = cons_actions[0].get("parameters") or {}
    cons_param_list: list[dict] = []
    if isinstance(cons_params_raw, dict):
        p_info = cons_params_raw.get(cons_param) or {}
        if isinstance(p_info, dict):
            cons_param_list = [{"name": cons_param, "contains": p_info.get("contains") or []}]
    elif isinstance(cons_params_raw, list):
        cons_param_list = [p for p in cons_params_raw if (p.get("name") or "").lower() == cons_param.lower()]
    cons_contains = _extract_contains(cons_param_list)

    # Determine selectability
    if not prod_contains or not cons_contains:
        selectable: object = "unknown"
        reason = (
            "One or both sides have no contains tags. "
            "Community apps often omit contains — selectability cannot be determined statically."
        )
        findings = [{"severity": "low", "code": "unknown_selectability",
                     "message": reason}]
    elif set(prod_contains) & set(cons_contains):
        selectable = True
        reason = f"Matching contains tags: {sorted(set(prod_contains) & set(cons_contains))}"
        findings = []
    else:
        selectable = False
        reason = f"No overlap between producer contains {prod_contains} and consumer contains {cons_contains}."
        findings = [{"severity": "warn", "code": "contains_mismatch", "message": reason}]

    result = {
        "ok": selectable is not False,
        "summary": f"Selectability: {selectable}. {reason[:120]}",
        "data": {
            "producer_app_id": prod_app_id,
            "producer_action": prod_action,
            "consumer_app_id": cons_app_id,
            "consumer_action": cons_action,
            "consumer_parameter": cons_param,
            "datapath": datapath or None,
            "selectable": selectable,
            "reason": reason,
            "producer_contains": prod_contains,
            "consumer_contains": cons_contains,
            "method": "schema_contains_match",
            "limitation": (
                "Phase A: schema-only. Edge provenance check (COA graph) not included — "
                "a matching contains tag does not guarantee a provenance edge exists."
            ),
        },
        "findings": findings,
        "errors": [],
    }
    return json.dumps(result, indent=2)


# ── #24 diff_playbook_versions + verify_layout_only_change ────────────────────

def _diff_coa_graphs(
    client: SoarApiClient, old_id: int, new_id: int
) -> tuple[dict, str | None]:
    """
    Fetch COA for both IDs, normalize volatiles, deep-diff.
    Returns (diff_result_dict, error_or_None).
    """
    old_cid, old_coa, err1 = _resolve_current_id(client, old_id)
    new_cid, new_coa, err2 = _resolve_current_id(client, new_id)
    errors = []
    if err1:
        errors.append(f"old_id: {err1}")
    if err2:
        errors.append(f"new_id: {err2}")
    if errors and (not old_coa or not new_coa):
        return {}, "; ".join(errors)

    old_norm = _normalize_coa_volatile(old_coa)
    new_norm = _normalize_coa_volatile(new_coa)

    raw_diffs = _deep_diff(old_norm, new_norm)
    change_categories: set[str] = set()
    changed_paths = []
    for d in raw_diffs:
        cat = _categorize_diff_path(d.get("path", ""))
        change_categories.add(cat)
        changed_paths.append({**d, "category": cat})

    is_layout_only = (change_categories == {"layout"}) or (len(change_categories) == 0)

    return {
        "old_id": old_id,
        "new_id": new_id,
        "old_current_id": old_cid,
        "new_current_id": new_cid,
        "change_categories": sorted(change_categories),
        "is_layout_only": is_layout_only,
        "changed_paths": changed_paths[:100],  # cap for MCP context size
        "total_diff_count": len(raw_diffs),
    }, None


def tool_diff_playbook_versions(
    client: SoarApiClient, config: McpServerConfig, args: dict
) -> str:
    old_id, err = _require_positive_int(args.get("old_id"), "old_id")
    if err:
        return err
    new_id, err = _require_positive_int(args.get("new_id"), "new_id")
    if err:
        return err

    diff_data, err = _diff_coa_graphs(client, old_id, new_id)
    if err:
        return json.dumps({
            "ok": False, "summary": f"Diff failed: {err}",
            "data": {}, "findings": [], "errors": [{"source": "coa", "message": err}],
        }, indent=2)

    cats = diff_data.get("change_categories", [])
    n_diffs = diff_data.get("total_diff_count", 0)
    result = {
        "ok": True,
        "summary": (
            f"{n_diffs} difference(s) in categories: {cats}. "
            + ("Layout-only change." if diff_data.get("is_layout_only") else "Behavioral changes detected.")
        ),
        "data": diff_data,
        "findings": (
            [] if diff_data.get("is_layout_only")
            else [{"severity": "warn", "code": "behavioral_change",
                   "message": f"Non-layout changes detected in categories: {cats}"}]
        ),
        "errors": [],
    }
    return json.dumps(result, indent=2)


def tool_verify_layout_only_change(
    client: SoarApiClient, config: McpServerConfig, args: dict
) -> str:
    before_id, err = _require_positive_int(args.get("before_id"), "before_id")
    if err:
        return err
    after_id, err = _require_positive_int(args.get("after_id"), "after_id")
    if err:
        return err

    diff_data, err = _diff_coa_graphs(client, before_id, after_id)
    if err:
        return json.dumps({
            "ok": False,
            "summary": f"Verification failed due to diff error: {err}",
            "data": {"layout_only": False, "error": "normalization_error"},
            "findings": [{"severity": "high", "code": "normalization_error", "message": err}],
            "errors": [{"source": "diff", "message": err}],
        }, indent=2)

    is_layout_only = diff_data.get("is_layout_only", False)
    result = {
        "ok": is_layout_only,
        "summary": (
            "PASS: only layout (x/y) changes detected."
            if is_layout_only else
            f"FAIL: non-layout changes in categories: {diff_data.get('change_categories', [])}"
        ),
        "data": {
            "layout_only": is_layout_only,
            "change_categories": diff_data.get("change_categories", []),
            "total_diff_count": diff_data.get("total_diff_count", 0),
            "before_id": before_id,
            "after_id": after_id,
        },
        "findings": (
            [] if is_layout_only
            else [{
                "severity": "high",
                "code": "behavioral_change",
                "message": (
                    f"Non-layout changes detected. save_playbook_layout_only must not proceed. "
                    f"Categories: {diff_data.get('change_categories', [])}"
                ),
            }]
        ),
        "errors": [],
    }
    return json.dumps(result, indent=2)


# ── #25 validate_playbook_bundle ──────────────────────────────────────────────

def tool_validate_playbook_bundle(
    client: SoarApiClient, config: McpServerConfig, args: dict
) -> str:
    import py_compile as _py_compile
    import shutil as _shutil
    import subprocess as _subprocess
    import tempfile as _tempfile
    import os as _os

    pid, err_msg = _require_positive_int(args.get("playbook_id"), "playbook_id")
    if err_msg:
        return err_msg

    current_id, coa_data, coa_err = _resolve_current_id(client, pid)
    errors = []
    if coa_err:
        errors.append({"source": "coa", "message": coa_err})

    checks: list[dict] = []

    # Check 1 — REST passed_validation flag.
    # SOAR 8.5 has no /rest/playbook/{id}/validate endpoint; do not probe it,
    # because that creates noisy server-side errors. The native flag is the
    # structure signal for this SOAR generation.
    rest_data, rest_err = client.get(f"playbook/{current_id}")
    if rest_err or not isinstance(rest_data, dict):
        checks.append({
            "name": "passed_validation",
            "status": "skipped",
            "message": f"Could not fetch REST playbook record: {rest_err}",
            "details": {},
        })
    else:
        pv = rest_data.get("passed_validation")
        checks.append({
            "name": "passed_validation",
            "status": "passed" if pv else ("failed" if pv is False else "skipped"),
            "message": f"passed_validation={pv}",
            "details": {},
        })

    # Check 2 — COA node warnings
    nodes, _ = _get_graph(client, current_id, coa_data)
    w_count = sum(
        1 for n in nodes
        if isinstance(n.get("warnings"), list) and len(n["warnings"]) > 0
    )
    checks.append({
        "name": "node_warnings",
        "status": "passed" if w_count == 0 else "failed",
        "message": f"{w_count} node(s) have stored COA warnings.",
        "details": {"warning_count": w_count},
    })

    # Check 3 — Python py_compile (AST-only, no execution)
    saved_python, python_source = _select_playbook_python(
        client,
        current_id,
        coa_data,
        rest_data if isinstance(rest_data, dict) else {},
        nodes,
    )

    if not saved_python:
        checks.append({
            "name": "python_compile",
            "status": "skipped",
            "message": (
                "No Python payload found in REST, COA, export archive, "
                "or code-node userCode snippets."
            ),
            "details": {},
        })
    else:
        tmp_path = None
        try:
            with _tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False, encoding="utf-8"
            ) as tf:
                tf.write(saved_python)
                tmp_path = tf.name
            _py_compile.compile(tmp_path, doraise=True)
            checks.append({
                "name": "python_compile",
                "status": "passed",
                "message": f"Python AST parse succeeded (source: {python_source}).",
                "details": {"source": python_source},
            })
        except _py_compile.PyCompileError as pce:
            checks.append({
                "name": "python_compile",
                "status": "failed",
                "message": f"Python compile error: {pce}",
                "details": {},
            })
        except Exception as exc:
            checks.append({
                "name": "python_compile",
                "status": "skipped",
                "message": f"Unexpected error during compile check: {type(exc).__name__}",
                "details": {},
            })
        finally:
            if tmp_path and _os.path.exists(tmp_path):
                _os.unlink(tmp_path)

    # Check 4 — lint (pyflakes preferred, pylint fallback; skip if absent)
    lint_binary = _shutil.which("pyflakes") or _shutil.which("pylint")
    if not lint_binary or not saved_python:
        checks.append({
            "name": "lint",
            "status": "skipped",
            "message": (
                "pyflakes/pylint not found in PATH." if not lint_binary
                else "Saved Python payload not available."
            ),
            "details": {},
        })
    else:
        tmp_path2 = None
        try:
            with _tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False, encoding="utf-8"
            ) as tf2:
                tf2.write(saved_python)
                tmp_path2 = tf2.name
            if "pyflakes" in lint_binary:
                cmd = [lint_binary, tmp_path2]
            else:
                cmd = [lint_binary, "--disable=all", "--enable=undefined-variable", tmp_path2]
            proc = _subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            lint_output = (proc.stdout + proc.stderr).strip()
            checks.append({
                "name": "lint",
                "status": "passed" if proc.returncode == 0 else "failed",
                "message": lint_output[:500] if lint_output else "No issues found.",
                "details": {"returncode": proc.returncode},
            })
        except _subprocess.TimeoutExpired:
            checks.append({"name": "lint", "status": "skipped",
                           "message": "Lint timed out after 30s.", "details": {}})
        except Exception as exc:
            checks.append({"name": "lint", "status": "skipped",
                           "message": f"Lint error: {type(exc).__name__}", "details": {}})
        finally:
            if tmp_path2 and _os.path.exists(tmp_path2):
                _os.unlink(tmp_path2)

    # Aggregate
    failed = [c for c in checks if c["status"] == "failed"]
    passed = [c for c in checks if c["status"] == "passed"]
    skipped = [c for c in checks if c["status"] == "skipped"]
    overall_ok = len(failed) == 0

    result = {
        "ok": overall_ok,
        "summary": f"{len(passed)}/{len(checks)} passed, {len(failed)} failed, {len(skipped)} skipped.",
        "data": {
            "current_id": current_id,
            "checks": checks,
        },
        "findings": [
            {"severity": "high", "code": "validation_failed",
             "message": f"Check '{c['name']}' failed: {c['message']}"}
            for c in failed
        ],
        "errors": errors,
    }
    return json.dumps(result, indent=2)


# ── #21 check_visual_editor_compat (aggregator) ───────────────────────────────

def tool_check_visual_editor_compat(
    client: SoarApiClient, config: McpServerConfig, args: dict
) -> str:
    pid, err_msg = _require_positive_int(args.get("playbook_id"), "playbook_id")
    if err_msg:
        return err_msg
    strict = bool(args.get("strict", False))

    all_findings: list[dict] = []
    errors: list[dict] = []

    # Step 1 — resolve current ID (abort if COA unreachable)
    current_id, coa_data, coa_err = _resolve_current_id(client, pid)
    if coa_err:
        errors.append({"source": "resolve", "message": coa_err})
    if current_id != pid:
        all_findings.append({
            "severity": "warn", "code": "stale_id", "source": "resolve",
            "message": f"Input ID {pid} is a previous revision; current draft is {current_id}.",
        })

    # Step 2 — COA summary (node/edge counts, custom names, warnings, errors)
    nodes, edges = _get_graph(client, current_id, coa_data)
    custom_name_count = sum(
        1 for n in nodes
        if (n.get("advanced") or {}).get("customName") or n.get("customName")
    )
    w_count = sum(
        1 for n in nodes
        if isinstance(n.get("warnings"), list) and len(n["warnings"]) > 0
    )
    e_count = sum(
        1 for n in nodes
        if isinstance(n.get("errors"), list) and len(n["errors"]) > 0
    )
    if custom_name_count:
        all_findings.append({
            "severity": "low", "code": "custom_name_count", "source": "coa_summary",
            "message": f"{custom_name_count} node(s) have custom display names — verify functionName consistency.",
        })
    if w_count:
        all_findings.append({
            "severity": "warn", "code": "node_warnings", "source": "coa_summary",
            "message": f"{w_count} node(s) have stored COA warnings.",
        })
    if e_count:
        all_findings.append({
            "severity": "high", "code": "node_errors", "source": "coa_summary",
            "message": f"{e_count} node(s) have stored COA errors.",
        })

    # Step 3 — Python drift check (inline; suppress response parsing overhead)
    drift_args = {"playbook_id": pid}
    drift_raw = tool_check_saved_generated_python_drift(client, config, drift_args)
    try:
        drift_result = json.loads(drift_raw)
        for f in drift_result.get("findings", []):
            all_findings.append({**f, "source": "drift"})
        for e in drift_result.get("errors", []):
            errors.append(e)
    except Exception:
        pass

    # Step 4 — Validation bundle
    val_args = {"playbook_id": pid}
    val_raw = tool_validate_playbook_bundle(client, config, val_args)
    try:
        val_result = json.loads(val_raw)
        for f in val_result.get("findings", []):
            all_findings.append({**f, "source": "validation"})
        for e in val_result.get("errors", []):
            errors.append(e)
        # Promote skipped checks to low-severity findings
        for chk in (val_result.get("data") or {}).get("checks", []):
            if chk.get("status") == "skipped":
                all_findings.append({
                    "severity": "low", "code": "validation_skipped", "source": "validation",
                    "message": f"Check '{chk['name']}' skipped: {chk['message']}",
                })
    except Exception:
        pass

    # Determine overall status
    sev_rank = {"high": 3, "warn": 2, "medium": 2, "low": 1}
    max_sev = max((sev_rank.get(f.get("severity", "low"), 0) for f in all_findings), default=0)

    if max_sev >= 3:
        status = "fail"
        ok = False
    elif max_sev >= 2:
        status = "warn"
        ok = not strict
    else:
        status = "pass" if all_findings else "pass"
        ok = True

    result = {
        "ok": ok,
        "summary": (
            f"VPE compat check: {status.upper()} — "
            f"{len(all_findings)} finding(s), {len(errors)} error(s). "
            f"Playbook id={current_id}, {len(nodes)} nodes, {len(edges)} edges."
        ),
        "data": {
            "input_id": pid,
            "current_id": current_id,
            "status": status,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "strict": strict,
        },
        "findings": all_findings,
        "errors": errors,
    }
    return json.dumps(result, indent=2)


def tool_audit_visual_playbook(
    client: SoarApiClient, config: McpServerConfig, args: dict
) -> str:
    """Read-only pre-edit audit (issue #69): one call → is this playbook safe to
    inspect/edit in the VPE? Composes COA summary + compat check + capability
    detection into a severity-tagged audit with operator recommendations.
    Consumes #68 so it never claims 'safe' when required data is unknown."""
    from soar_mcp_capabilities import detect_capabilities
    from soar_mcp_envelope import envelope_response, normalize_output_format

    fmt = normalize_output_format(args.get("output_format"))
    pid, err_msg = _require_positive_int(args.get("playbook_id"), "playbook_id")
    if err_msg:
        return err_msg

    findings: list[dict] = []
    errors: list[dict] = []
    data: dict = {"input_id": pid}

    # 1. COA summary (trigger, type, counts, passed_validation).
    try:
        summ = json.loads(tool_get_playbook_coa_summary(client, config, {"playbook_id": pid}))
        sd = summ.get("data") or {}
        data.update({
            "current_id": sd.get("current_id"),
            "name": sd.get("name"),
            "trigger": sd.get("trigger"),
            "playbook_type": sd.get("playbook_type"),
            "passed_validation": sd.get("passed_validation"),
            "node_count": sd.get("node_count"),
            "edge_count": sd.get("edge_count"),
            "warning_count": sd.get("warning_count"),
            "error_count": sd.get("error_count"),
        })
        for e in summ.get("errors", []):
            errors.append(e)
    except Exception as exc:
        errors.append({"safe_message": f"coa_summary failed: {type(exc).__name__}"})

    # 2. Compat findings (reuse the working aggregator; do not modify it).
    try:
        compat = json.loads(tool_check_visual_editor_compat(client, config, {"playbook_id": pid}))
        for f in compat.get("findings", []):
            findings.append(f)
        for e in compat.get("errors", []):
            errors.append(e)
    except Exception as exc:
        errors.append({"safe_message": f"compat_check failed: {type(exc).__name__}"})

    # 3. Capability context (#68): don't promise 'safe' when data is unknown.
    caps = detect_capabilities(client, int(data.get("current_id") or pid))
    data["capabilities"] = caps.to_dict()
    inspectable = caps.coa_graph_extractable or caps.export_fallback_available
    python_known = caps.python_source != "none"

    # 4. Verdict — explicit unknown vs pass/warn/fail.
    sev_rank = {"high": 3, "warn": 2, "medium": 2, "low": 1, "info": 0}
    max_sev = max((sev_rank.get(f.get("severity", "low"), 0) for f in findings), default=0)
    if not inspectable:
        verdict = "unknown"
    elif max_sev >= 3 or data.get("error_count"):
        verdict = "fail"
    elif max_sev >= 2 or not python_known:
        verdict = "warn"
    else:
        verdict = "pass"
    data["verdict"] = verdict

    # 5. Operator recommendations.
    recs: list[str] = []
    if verdict == "unknown":
        recs.append("COA graph and export archive are both unavailable — cannot audit; "
                    "check connectivity/permissions before editing.")
    if not python_known:
        recs.append("Generated Python could not be inspected — drift status is unknown; "
                    "review helper functions manually before saving in the VPE.")
    if data.get("error_count"):
        recs.append("Resolve stored node errors before editing.")
    if any(f.get("code") == "stale_id" for f in findings):
        recs.append(f"You passed a stale revision; edit the current draft "
                    f"(id={data.get('current_id')}).")
    if not recs:
        recs.append("No blocking issues detected — safe to inspect/edit.")
    data["recommendations"] = recs

    ok = verdict in ("pass", "warn")
    summary = (f"Visual playbook audit for '{data.get('name') or pid}' "
               f"(id={data.get('current_id') or pid}): {verdict.upper()} — "
               f"{data.get('node_count')} nodes, {len(findings)} finding(s).")
    return envelope_response(ok, summary, data=data, findings=findings,
                             errors=errors, fmt=fmt)


# ── #29 save_playbook_layout_only (WRITE, guarded) ────────────────────────────

def tool_save_playbook_layout_only(
    client: SoarApiClient, config: McpServerConfig, args: dict
) -> str:
    pid, err_msg = _require_positive_int(args.get("playbook_id"), "playbook_id")
    if err_msg:
        return err_msg

    node_positions = args.get("node_positions") or {}
    if not isinstance(node_positions, dict) or not node_positions:
        return json.dumps({
            "ok": False,
            "summary": "Error: node_positions must be a non-empty dict of functionId -> {x, y}.",
            "data": {}, "findings": [], "errors": [],
        }, indent=2)

    expected_hash = args.get("expected_hash")
    # Default dry_run to True — the first invocation should always be a dry run
    dry_run = bool(args.get("dry_run", True))

    # Step 1 — resolve current ID; reject stale inputs
    current_id, coa_data, coa_err = _resolve_current_id(client, pid)
    if coa_err:
        return json.dumps({
            "ok": False,
            "summary": f"Cannot resolve current draft: {coa_err}",
            "data": {}, "findings": [],
            "errors": [{"source": "resolve", "message": coa_err}],
        }, indent=2)
    if current_id != pid:
        return json.dumps({
            "ok": False,
            "summary": (
                f"Input ID {pid} is a stale revision. "
                f"Resolve to current draft {current_id} first."
            ),
            "data": {"current_id": current_id, "input_id": pid},
            "findings": [{"severity": "high", "code": "stale_id",
                          "message": f"Use current_id={current_id} not {pid}."}],
            "errors": [],
        }, indent=2)

    # Step 2 — hash check if provided
    if expected_hash:
        # VERIFY: does the COA response contain a hash field?
        actual_hash = coa_data.get("hash") or coa_data.get("coa_hash")
        if actual_hash and actual_hash != expected_hash:
            return json.dumps({
                "ok": False,
                "summary": "Hash mismatch — COA state changed since expected_hash was captured.",
                "data": {"expected": expected_hash, "actual": actual_hash},
                "findings": [{"severity": "high", "code": "hash_mismatch",
                              "message": "COA state changed since expected_hash was captured."}],
                "errors": [],
            }, indent=2)

    # Step 3 — apply positions to in-memory copy and verify layout-only
    import copy as _copy
    modified_coa = _copy.deepcopy(coa_data)
    nodes, _ = _get_coa_nodes_edges(modified_coa)
    applied = []
    not_found = []
    for n in nodes:
        fn_id = str(n.get("functionId") or n.get("function_id") or "")
        if fn_id in node_positions:
            pos = node_positions[fn_id]
            # VERIFY: position field names — may be "left"/"top" or "x"/"y"
            if "left" in n or "top" in n:
                n["left"] = pos.get("x", n.get("left", 0))
                n["top"] = pos.get("y", n.get("top", 0))
            else:
                n["x"] = pos.get("x", n.get("x", 0))
                n["y"] = pos.get("y", n.get("y", 0))
            applied.append(fn_id)
    not_found = [fid for fid in node_positions if fid not in applied]

    # Step 4 — verify that the proposed change is layout-only
    diff_pairs = _deep_diff(
        _normalize_coa_volatile(coa_data),
        _normalize_coa_volatile(modified_coa),
    )
    non_layout = [
        d for d in diff_pairs
        if _categorize_diff_path(d.get("path", "")) != "layout"
    ]

    if non_layout:
        return json.dumps({
            "ok": False,
            "summary": "Internal error: position update would change non-layout fields. Aborting.",
            "data": {"non_layout_diffs": non_layout[:10]},
            "findings": [{"severity": "high", "code": "behavioral_change",
                          "message": "Position update leaked into non-layout fields."}],
            "errors": [],
        }, indent=2)

    # Step 5 — dry_run: return preview without writing
    if dry_run:
        return json.dumps({
            "ok": True,
            "summary": (
                f"DRY RUN — {len(applied)} node(s) would be repositioned, "
                f"{len(not_found)} functionId(s) not found in COA. "
                "Set dry_run=false to write after reviewing."
            ),
            "data": {
                "playbook_id": current_id,
                "dry_run": True,
                "applied": applied,
                "not_found": not_found,
                "diff_count": len(diff_pairs),
                "is_layout_only": True,
            },
            "findings": (
                [{"severity": "low", "code": "positions_not_found",
                  "message": f"functionId(s) not in COA: {not_found}"}]
                if not_found else []
            ),
            "errors": [],
        }, indent=2)

    # Step 6 — actual write (dry_run=false)
    # VERIFY: COA write endpoint — does SOAR 8.5 expose PUT /coa/playbooks/{id}?
    # VERIFY: Does SOAR expose PATCH /coa/playbooks/{id} for partial position updates?
    # Until live-verified, refuse the write and give instructions.
    return json.dumps({
        "ok": False,
        "summary": (
            "Write blocked: the COA write endpoint (/coa/playbooks/{id} PUT or PATCH) "
            "has not been live-verified on this SOAR instance. "
            "Run with dry_run=true first, then probe the endpoint and update VERIFICATION.md."
        ),
        "data": {
            "playbook_id": current_id,
            "dry_run": False,
            "applied_in_memory": applied,
            "not_found": not_found,
        },
        "findings": [{
            "severity": "high",
            "code": "write_endpoint_unverified",
            "message": (
                "COA PATCH/PUT endpoint not yet verified on SOAR 8.5. "
                "Steps to unlock: (1) confirm /coa/playbooks/{id} accepts PUT/PATCH, "
                "(2) document field format in VERIFICATION.md, "
                "(3) remove this guard from tool_save_playbook_layout_only()."
            ),
        }],
        "errors": [],
    }, indent=2)


# ==============================================================================
# Dispatcher
# ==============================================================================

def tool_generate_mcp_client_config(
    client: SoarApiClient, config: McpServerConfig, args: dict
) -> str:
    """Generate copy-safe MCP client config snippets (issue #72).

    Read-only. Uses the real handler endpoint but ALWAYS a placeholder token —
    never the configured asset auth_token (that would leak a credential).
    """
    import json as _json

    endpoint = (
        config.mcp_endpoint
        or f"{client._base_url}/rest/handler/<soarmcpserver_appid>/<asset_name>"
    )
    ph = "YOUR_SOAR_AUTH_TOKEN"        # placeholder — never a real token
    env = "${env:SOAR_MCP_TOKEN}"      # env-var reference for Cursor/shell setups

    claude_desktop = {"mcpServers": {"splunk-soar": {
        "url": endpoint, "headers": {"ph-auth-token": ph}}}}
    claude_code = {"mcpServers": {"splunk-soar": {
        "type": "http", "url": endpoint, "headers": {"ph-auth-token": ph}}}}
    cursor = {"mcpServers": {"splunk-soar": {
        "url": endpoint, "headers": {"ph-auth-token": env}}}}
    cli = (f'claude mcp add --transport http splunk-soar "{endpoint}" '
           f'-H "ph-auth-token: {ph}"')

    lines = [
        "MCP client configuration (replace the placeholder token with your own):",
        "",
        "# Claude Desktop — claude_desktop_config.json",
        _json.dumps(claude_desktop, indent=2),
        "",
        "# Claude Code — ~/.claude.json",
        _json.dumps(claude_code, indent=2),
        "",
        "# Claude Code CLI",
        cli,
        "",
        "# Cursor — ~/.cursor/mcp.json (token via env var; run: "
        'export SOAR_MCP_TOKEN="<your-token>")',
        _json.dumps(cursor, indent=2),
        "",
        "Troubleshooting: 404 → check the handler path segment is your asset name; "
        "401 → token invalid; SSL error → self-signed cert (set ssl_verify=false only "
        "for test instances).",
    ]
    return "\n".join(lines)


TOOL_SCHEMAS["generate_mcp_client_config"] = {
    "description": (
        "Generate copy-ready MCP client configuration snippets (Claude Desktop, "
        "Claude Code, Cursor, CLI) for this SOAR MCP endpoint. Read-only. Token "
        "values are always placeholders — never the real auth token."
    ),
    "inputSchema": {"type": "object", "properties": {}},
}

def tool_diagnose_soar_mcp_environment(
    client: SoarApiClient, config: McpServerConfig, args: dict
) -> str:
    """Read-only diagnostics: is the installed MCP endpoint usable, and why not?
    (issue #67). First consumer of the structured envelope (#74), the posture
    report (#51), and the error classifier (#70). Never returns token values."""
    from soar_mcp_config import build_posture_report
    from soar_mcp_envelope import envelope_response, normalize_output_format

    fmt = normalize_output_format(args.get("output_format"))
    findings: list[dict] = []
    errors: list[dict] = []

    endpoint = config.mcp_endpoint or "(unknown — run Test Connectivity)"
    auth_present = bool(getattr(client, "_auth_token", ""))
    if not auth_present:
        findings.append({"severity": "error", "code": "no_auth_token",
                         "message": "No ph-auth-token was presented on this request."})

    # Safe reachability probe: GET /rest/version.
    soar_version = None
    handler_reachable = False
    ver, ver_err = client.get("version")
    if ver_err:
        info = None
        errors.append({"category": "probe", "safe_message": ver_err,
                       "endpoint_category": "rest/version"})
        findings.append({"severity": "warn", "code": "version_probe_failed",
                         "message": f"/rest/version probe failed: {ver_err}"})
    else:
        handler_reachable = True
        if isinstance(ver, dict):
            soar_version = ver.get("version") or ver.get("rest_version")

    posture = build_posture_report(config)
    for flag in posture.get("risk_flags", []):
        findings.append({"severity": "warn", "code": flag,
                         "message": f"Security posture: {flag}"})

    data = {
        "app_version": config.server_version,
        "mcp_endpoint": endpoint,
        "auth_token_present": auth_present,   # presence only, never the value
        "handler_reachable": handler_reachable,
        "soar_version": soar_version,
        "enabled_tool_count": len(config.enabled_tools),
        "security_posture": posture,
    }
    ok = auth_present and handler_reachable and not any(
        f.get("severity") == "error" for f in findings
    )
    summary = (
        "SOAR MCP environment looks usable."
        if ok else
        "SOAR MCP environment has issues — see findings."
    )
    return envelope_response(ok, summary, data=data, findings=findings,
                             errors=errors, fmt=fmt)


TOOL_SCHEMAS["diagnose_soar_mcp_environment"] = {
    "description": (
        "Read-only diagnostics for this SOAR MCP endpoint: reports app version, "
        "endpoint shape, handler reachability, a safe /rest/version probe, and the "
        "security posture with actionable findings. Never returns token values. "
        "Use output_format=json for structured output."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "output_format": {
                "type": "string",
                "description": "Output format: 'text' (default) or 'json'.",
                "enum": ["text", "json"],
            },
        },
    },
}


def tool_detect_soar_capabilities(
    client: SoarApiClient, config: McpServerConfig, args: dict
) -> str:
    """Read-only: detect how this SOAR instance's playbook/COA surface behaves
    (issue #68). Probes a known-good playbook and reports the capability map."""
    from soar_mcp_capabilities import detect_capabilities
    from soar_mcp_envelope import envelope_response, normalize_output_format

    fmt = normalize_output_format(args.get("output_format"))

    pid, err = _require_positive_int(args.get("playbook_id"), "playbook_id") \
        if args.get("playbook_id") is not None else (None, None)
    if err:
        return err
    if pid is None:
        # Auto-pick the first available playbook as the probe sample.
        data, list_err = client.get("playbook", params={"page_size": 1})
        items = data if isinstance(data, list) else (data or {}).get("data", [])
        if not items:
            return envelope_response(
                False, "No playbook available to probe capabilities.",
                errors=[{"safe_message": list_err or "no playbooks found"}], fmt=fmt)
        pid = items[0].get("id")

    report = detect_capabilities(client, int(pid))
    findings = [{"severity": "info", "code": n} for n in report.notes]
    ok = report.coa_endpoint_available or report.export_fallback_available
    summary = (
        f"Capabilities probed via playbook {pid}: "
        f"coa={'live' if report.coa_graph_extractable else 'summary-only' if report.coa_endpoint_available else 'unavailable'}, "
        f"python_source={report.python_source}, export_fallback={report.export_fallback_available}."
    )
    return envelope_response(ok, summary, data=report.to_dict(),
                             findings=findings, fmt=fmt)


TOOL_SCHEMAS["detect_soar_capabilities"] = {
    "description": (
        "READ — Detect how this SOAR instance's playbook/COA surface actually "
        "behaves (COA graph availability, export fallback, Python payload source, "
        "validation method). Probes one known-good playbook. output_format=text|json."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "playbook_id": {"type": "integer", "description": "Playbook to probe (default: first available)."},
            "output_format": {"type": "string", "enum": ["text", "json"], "description": "Output format (default text)."},
        },
    },
}

TOOL_SCHEMAS["audit_visual_playbook"] = {
    "description": (
        "READ — Pre-edit audit of a Visual Editor playbook: one call returns "
        "stale/current status, node/edge counts, warnings/errors, trigger/type, "
        "Python payload source, validation + drift summary, and operator "
        "recommendations. Verdict is pass/warn/fail/unknown — never claims 'safe' "
        "when required data is unavailable. output_format=text|json."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "playbook_id": {"type": "integer", "description": "Playbook to audit (current or stale — resolved automatically)."},
            "output_format": {"type": "string", "enum": ["text", "json"], "description": "Output format (default text)."},
        },
        "required": ["playbook_id"],
    },
}


TOOL_SCHEMAS["delete_container"] = {
    "description": (
        "WRITE — Delete a test container by ID to clean up after playbook self-tests. "
        "Requires the test harness to be enabled. Refuses to delete containers not "
        "labelled 'test' unless confirm=true. Never use on production."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "container_id": {"type": "integer", "description": "The test container/case ID to delete."},
            "confirm": {"type": "boolean", "description": "Delete even if the label is not 'test' (default false).", "default": False},
        },
        "required": ["container_id"],
    },
}


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
    # Playbook-Discovery & Build tools (v1.6.0+)
    "list_apps": tool_list_apps,
    "list_assets": tool_list_assets,
    "get_action_schema": tool_get_action_schema,
    "export_playbook": tool_export_playbook,
    # Write tools (v1.6.0+)
    "import_playbook": tool_import_playbook,
    "create_container": tool_create_container,
    # COA Visual Editor tools (v1.6.3+)
    "resolve_playbook_current_id": tool_resolve_playbook_current_id,
    "get_playbook_identity_map": tool_get_playbook_identity_map,
    "get_playbook_coa_summary": tool_get_playbook_coa_summary,
    "list_playbook_nodes": tool_list_playbook_nodes,
    "list_playbook_edges": tool_list_playbook_edges,
    "check_saved_generated_python_drift": tool_check_saved_generated_python_drift,
    "check_datapath_selectability": tool_check_datapath_selectability,
    "diff_playbook_versions": tool_diff_playbook_versions,
    "verify_layout_only_change": tool_verify_layout_only_change,
    "validate_playbook_bundle": tool_validate_playbook_bundle,
    "check_visual_editor_compat": tool_check_visual_editor_compat,
    # Write tools (v1.6.3+)
    "save_playbook_layout_only": tool_save_playbook_layout_only,
    # Client config helper (v1.8.0+)
    "generate_mcp_client_config": tool_generate_mcp_client_config,
    # Test-harness cleanup (v1.8.0+)
    "delete_container": tool_delete_container,
    # Diagnostics (v1.9.0+)
    "diagnose_soar_mcp_environment": tool_diagnose_soar_mcp_environment,
    # Capability detection (v1.10.0+)
    "detect_soar_capabilities": tool_detect_soar_capabilities,
    # Visual playbook pre-edit audit (v1.11.0+)
    "audit_visual_playbook": tool_audit_visual_playbook,
}


# ── Write-tool confirmation gate (issue #50) ──────────────────────────────────
# Write tools are those with a handler that are not read-only.
_WRITE_TOOLS: frozenset[str] = frozenset(_TOOL_HANDLERS) - READ_ONLY_TOOLS


class _ConfirmStore:
    """In-process, TTL-bound confirmation tokens keyed on (tool, args).

    Per-process only (like the token rate limiter); a confirm token issued on
    one worker is not valid on another. That is acceptable — worst case the
    client is asked to confirm again.
    """

    def __init__(self) -> None:
        self._d: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(tool: str, args: dict) -> str:
        blob = tool + "|" + json.dumps(args, sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()

    def issue(self, tool: str, args: dict, ttl: float = 300.0) -> str:
        token = "confirm_" + secrets.token_urlsafe(9)
        with self._lock:
            self._d[token] = (self._key(tool, args), time.time() + ttl)
        return token

    def consume(self, token: str, tool: str, args: dict) -> bool:
        with self._lock:
            entry = self._d.get(token)
            if not entry:
                return False
            key, exp = entry
            if time.time() > exp or key != self._key(tool, args):
                self._d.pop(token, None)
                return False
            self._d.pop(token, None)
            return True


_confirm_store = _ConfirmStore()


def _maybe_require_confirmation(
    tool_name: str, arguments: dict, config: McpServerConfig
) -> Optional[str]:
    """Return a confirmation-preview string if the call must be confirmed first,
    or None to proceed. Two-step commit for write tools when
    require_confirmation is enabled (issue #50)."""
    if not getattr(config, "require_confirmation", False):
        return None
    if tool_name not in _WRITE_TOOLS:
        return None
    # Layout dry-run preview is read-only and safe — no confirmation needed.
    if tool_name == "save_playbook_layout_only" and arguments.get("dry_run", True):
        return None

    key_args = {k: v for k, v in arguments.items() if k != "confirm_token"}
    provided = arguments.get("confirm_token")
    if provided and _confirm_store.consume(str(provided), tool_name, key_args):
        return None  # confirmed — proceed

    token = _confirm_store.issue(tool_name, key_args)
    return (
        "⚠️ Confirmation required — this SOAR MCP instance has require_confirmation "
        "enabled for write operations.\n"
        f"  Tool:      {tool_name}\n"
        f"  Arguments: {json.dumps(key_args, default=str)[:400]}\n\n"
        f"To execute, call {tool_name} again with the SAME arguments plus:\n"
        f'  confirm_token = "{token}"\n'
        "The token is valid for 5 minutes and only for these exact arguments."
    )


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
    gate = _maybe_require_confirmation(tool_name, arguments or {}, config)
    if gate is not None:
        return gate
    try:
        result = handler(client, config, arguments or {})
        if config.log_tool_calls:
            logger.info("[MCP Tool] Called '%s' with args=%s", tool_name, list((arguments or {}).keys()))
        return result
    except Exception as exc:
        logger.exception("[MCP Tool] Unexpected error in tool '%s': %s", tool_name, exc)
        return f"Internal error executing tool '{tool_name}': {type(exc).__name__}"
