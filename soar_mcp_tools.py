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
import re
from typing import Any, Optional

import requests

from soar_mcp_config import McpServerConfig

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

logger = logging.getLogger(__name__)

# ── SOAR severity ordering (for min_severity filtering) ───────────────────────
_SEVERITY_ORDER = {"high": 4, "medium": 3, "low": 2, "informational": 1, "": 0}

# ── SOAR status labels ─────────────────────────────────────────────────────────
_VALID_STATUSES = {"open", "closed", "resolved", "new"}
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
        except requests.exceptions.Timeout:
            return None, f"SOAR REST API timed out after {self._config.timeout}s"
        except requests.exceptions.ConnectionError as e:
            return None, f"Connection error: {e}"
        except Exception as e:
            return None, f"Unexpected error: {type(e).__name__}"

    def get_binary(self, path: str, params: dict | None = None) -> tuple[bytes | None, str | None]:
        """GET request returning raw bytes (for binary endpoints like playbook export)."""
        url = f"{self._base_url}/rest/{path.lstrip('/')}"
        try:
            resp = self._session.get(url, params=params, timeout=self._config.timeout)
            if resp.status_code == 401:
                return None, "Authentication failed (HTTP 401). Check ph-auth-token."
            if resp.status_code == 403:
                return None, "Access denied (HTTP 403). Token may lack required permissions."
            if resp.status_code == 404:
                return None, "Resource not found (HTTP 404)."
            if resp.status_code >= 400:
                return None, f"SOAR API error HTTP {resp.status_code}: {resp.text[:200]}"
            return resp.content, None
        except requests.exceptions.Timeout:
            return None, f"SOAR REST API timed out after {self._config.timeout}s"
        except requests.exceptions.SSLError as e:
            return None, f"SSL error: {e}"
        except requests.exceptions.ConnectionError as e:
            return None, f"Connection error: {e}"
        except Exception as e:
            return None, f"Unexpected error: {type(e).__name__}"

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
        except requests.exceptions.Timeout:
            return None, f"COA endpoint timed out after {self._config.timeout}s"
        except requests.exceptions.SSLError as e:
            return None, f"SSL error reaching COA endpoint: {e}"
        except requests.exceptions.ConnectionError as e:
            return None, f"Connection error reaching COA endpoint: {e}"
        except Exception as e:
            return None, f"Unexpected error reaching COA endpoint: {type(e).__name__}"

    def _handle_response(self, resp: requests.Response) -> tuple[Any, str | None]:
        if resp.status_code == 401:
            return None, "Authentication failed (HTTP 401). Check ph-auth-token in the MCP client config."
        if resp.status_code == 403:
            # Surface SOAR's actual response body — do not swallow it.
            # The caller (e.g. tool_import_playbook) adds context-specific guidance.
            try:
                err_body = resp.json()
                msg = err_body.get("message") or err_body.get("error") or resp.text[:300]
            except Exception:
                msg = resp.text[:300]
            return None, f"Access denied (HTTP 403): {msg}"
        if resp.status_code == 404:
            return None, "Resource not found (HTTP 404)."
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
    total = data.get("count", len(items)) if isinstance(data, dict) else len(items)

    # Apply min_severity filter if configured
    if config.min_severity:
        min_sev_val = _SEVERITY_ORDER.get(config.min_severity, 0)
        items = [c for c in items if _SEVERITY_ORDER.get(c.get("severity", "").lower(), 0) >= min_sev_val]

    # Apply allowed_labels filter if configured
    if config.allowed_labels:
        items = [c for c in items if c.get("label", "") in config.allowed_labels]

    if not items:
        return "No cases found matching the specified filters."

    suffix = f" (showing {len(items)} of {total} — use filters to narrow)" if total > limit else ""
    lines = [f"Found {len(items)} case(s){suffix}:\n"]
    for c in items[:limit]:
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
    total = data.get("count", len(items)) if isinstance(data, dict) else len(items)
    if not items:
        return f"No cases found matching '{query}'."

    suffix = f" (showing {len(items)} of {total} — refine query for more)" if total > limit else ""
    lines = [f"Found {len(items)} case(s) matching '{query}'{suffix}:\n"]
    for c in items[:limit]:
        lines.append(_fmt_case(c))
    return "\n".join(lines) + (_disclaimer() if config.advisory_disclaimer else "")


def tool_list_artifacts(client: SoarApiClient, config: McpServerConfig, args: dict) -> str:
    """List artifacts for a case."""
    case_id, err_msg = _require_positive_int(args.get("case_id"), "case_id")
    if err_msg:
        return err_msg
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

    body = {
        "container_id": case_id,
        "name": name,
        "label": args.get("label", "artifact"),
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
            "Error: create_container also requires enable_test_harness = true in the "
            "[safety] section of mcp.conf. This prevents accidental case creation in "
            "production SOAR instances. Set it to true only on test/dev instances."
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
    return int(raw_current), coa_data, None


def _get_coa_nodes_edges(coa_data: dict) -> tuple[list, list]:
    """
    Extract nodes and edges from a COA graph response.

    Known shapes (issue #30 — second fix):
      A) export archive JSON:   coa_data["coa"]["data"]["nodes"]
      B) live /coa/playbooks/{id} on SOAR 8.5 (no outer "coa" wrapper):
                                coa_data["data"]["nodes"]
      C) flat top-level:        coa_data["nodes"]

    Nodes may be a dict keyed by string node-id — normalised to list.
    Edges field may be "connections" or "edges".
    """
    coa_sub = coa_data.get("coa") or {}

    # data_sub: prefer shape A (coa.data), then shape B (data at top level)
    data_sub = coa_sub.get("data") or coa_data.get("data") or {}

    nodes_raw = (
        data_sub.get("nodes")        # shapes A and B
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
        or coa_sub.get("connections") or coa_sub.get("edges")
        or coa_data.get("connections") or coa_data.get("edges")
        or coa_data.get("links")
        or []
    )
    edges: list = edges_raw if isinstance(edges_raw, list) else []
    return nodes, edges


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
            parts.append(f"# --- {fn_name} ---\n{code}")
    return "\n\n".join(parts) if parts else None


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
    trigger = rest_data.get("trigger") or coa_data.get("trigger", "")

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

    # Collect COA userCode blocks from code-type nodes
    # VERIFY: field name "userCode" inside a code node — may be "user_code" or "code"
    coa_functions: set[str] = set()
    for n in nodes:
        if (n.get("type") or "").lower() == "code":
            user_code = n.get("userCode") or n.get("user_code") or n.get("code") or ""
            if user_code:
                try:
                    tree = _ast.parse(user_code)
                    for node_obj in _ast.walk(tree):
                        if isinstance(node_obj, _ast.FunctionDef):
                            coa_functions.add(node_obj.name)
                except SyntaxError:
                    pass

    # Fetch saved Python payload from REST
    # VERIFY: field name for saved Python in /rest/playbook/{id} — may be "code", "script", or "playbook_run_data"
    rest_data, rest_err = client.get(f"playbook/{current_id}")
    saved_python: Optional[str] = None
    python_payload_available = False
    if isinstance(rest_data, dict):
        saved_python = (
            rest_data.get("code")
            or rest_data.get("script")
            or rest_data.get("playbook_run_data")
        )
        if saved_python:
            python_payload_available = True

    if not python_payload_available:
        result = {
            "ok": True,
            "summary": "Python payload not available in REST response — check skipped.",
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
                "skip_reason": "saved Python payload not found in /rest/playbook response — VERIFY field name",  # noqa
            },
            "findings": [],
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

    # Check 1 — SOAR structure validation endpoint
    # SOAR 8.5 confirmed: /rest/playbook/{id}/validate does not exist → HTTP 400/404.
    # passed_validation (check 2) serves as the structure signal on 8.5.
    val_data, val_err = client.get(f"playbook/{current_id}/validate")
    if val_err and ("404" in str(val_err) or "400" in str(val_err)):
        checks.append({
            "name": "validate_structure",
            "status": "skipped",
            "message": (
                "SOAR 8.5: no dedicated /rest/playbook/{id}/validate endpoint "
                "(HTTP 400/404). Use passed_validation flag (check 2) as structure signal."
            ),
            "details": {},
        })
    elif val_err:
        checks.append({
            "name": "validate_structure",
            "status": "skipped",
            "message": f"Validation endpoint error: {val_err}",
            "details": {},
        })
    else:
        # VERIFY: success signal in validation endpoint response
        val_passed = (
            val_data.get("success", True)
            if isinstance(val_data, dict) else True
        )
        checks.append({
            "name": "validate_structure",
            "status": "passed" if val_passed else "failed",
            "message": (val_data.get("message", "") if isinstance(val_data, dict) else ""),
            "details": val_data if isinstance(val_data, dict) else {},
        })

    # Check 2 — REST passed_validation flag
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

    # Check 3 — COA node warnings
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

    # Check 4 — Python py_compile (AST-only, no execution)
    # SOAR 8.5: Python is not a REST field.  Priority order:
    #   1. REST code field (rarely populated, kept for completeness)
    #   2. COA userCode blocks (code-type nodes only)
    #   3. Export archive .py file — covers action/decision/utility-only playbooks (#31 fix)
    import io as _io
    import tarfile as _tarfile

    saved_python = None
    python_source = None
    if isinstance(rest_data, dict):
        saved_python = (
            rest_data.get("code")
            or rest_data.get("script")
            or rest_data.get("playbook_run_data")
        )
        if saved_python:
            python_source = "rest_field"
    if not saved_python:
        saved_python = _extract_python_from_coa(nodes)
        if saved_python:
            python_source = "coa_usercode"
    if not saved_python:
        # Fetch export archive and extract the SOAR-generated .py file.
        # SOAR generates Python for all node types (action, decision, utility, code),
        # so the .py in the archive covers cases where COA has no code-type nodes.
        export_content, _ = client.get_binary(f"playbook/{current_id}/export")
        if export_content:
            try:
                buf = _io.BytesIO(export_content)
                with _tarfile.open(fileobj=buf, mode="r:*") as tarf:
                    for member in tarf.getmembers():
                        if member.name.endswith(".py"):
                            fobj = tarf.extractfile(member)
                            if fobj:
                                saved_python = fobj.read().decode("utf-8", errors="replace")
                                python_source = "export_archive"
                                break
            except Exception:
                pass  # archive extraction failed — proceed without compile check

    if not saved_python:
        checks.append({
            "name": "python_compile",
            "status": "skipped",
            "message": (
                "No Python payload found — REST record has no code field, "
                "COA contains no code-type nodes with userCode, "
                "and export archive extraction failed or returned no .py file."
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

    # Check 5 — lint (pyflakes preferred, pylint fallback; skip if absent)
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
