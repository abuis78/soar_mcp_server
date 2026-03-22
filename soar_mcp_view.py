#!/usr/bin/env python3
"""
SOAR MCP Server — Custom Widget View

Renders the 'Get MCP Config' action result as an interactive widget that
auto-builds the Claude Desktop and Claude Code JSON configuration snippets,
with one-click copy buttons so analysts can paste them directly.

Copyright 2026 Andreas Buis
"""

from __future__ import annotations

import json

# Known write tools — used to split enabled_tools into read vs. write counts
_WRITE_TOOLS = frozenset([
    "add_case_note",
    "run_playbook",
    "update_case_status",
    "update_case_severity",
    "update_case_owner",
    "create_artifact",
])


def display_mcp_config(provides: list, all_app_runs: list, context: dict) -> str:
    """
    Entry point called by SOAR for the 'get_mcp_config' action widget.

    In SOAR's view renderer, each item in action_results is a plain dict
    with keys: "data" (list), "status" (str), "message" (str), "summary",
    "parameter" — NOT an ActionResult object with .get_data() methods.

    Returns the template filename; SOAR renders it with the context dict.
    """
    context["records"] = []

    # Try to derive the SOAR base URL from the Django request object
    # so the generated config snippets contain the real hostname.
    soar_base_url = _derive_soar_base_url(context)

    for summary, action_results, playbook_name in all_app_runs:
        for result in action_results:
            # result is a dict: {"data": [...], "status": "...", "message": "..."}
            data_list = result.get("data", [])
            status = result.get("status", "success")
            message = result.get("message", "")

            if data_list:
                data = data_list[0] if isinstance(data_list, list) else data_list
            else:
                data = {}

            record = _build_record(data, status, message, soar_base_url)
            context["records"].append(record)

    return "soar_mcp_view.html"


def _derive_soar_base_url(context: dict) -> str:
    """
    Attempt to extract the SOAR base URL from the Django request object
    that SOAR passes in the view context. Falls back to a placeholder.
    """
    try:
        request = context.get("request")
        if request:
            scheme = getattr(request, "scheme", "https")
            host = request.get_host()          # e.g. "soar.example.com:8443"
            return f"{scheme}://{host}"
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_record(data: dict, status: str, message: str, soar_base_url: str = "") -> dict:
    """
    Normalise raw action result data into the fields the template needs.
    """
    enabled_tools = data.get("enabled_tools", [])
    disabled_tools = data.get("disabled_tools", [])
    max_results = data.get("max_results", 50)
    ssl_verify = data.get("ssl_verify", True)
    log_tool_calls = data.get("log_tool_calls", True)
    server_name = data.get("server_name", "Splunk SOAR MCP Server")
    server_version = data.get("server_version", "1.1.0")
    protocol_version = data.get("protocol_version", "2024-11-05")
    advisory_disclaimer = data.get("advisory_disclaimer", True)
    min_severity = data.get("min_severity", "")
    max_items_per_case = data.get("max_items_per_case", 200)

    # Build the MCP endpoint URL — prefer data field, then derived host, then placeholder
    endpoint_from_data = data.get("mcp_endpoint", "")
    if endpoint_from_data:
        mcp_endpoint = endpoint_from_data
    elif soar_base_url:
        mcp_endpoint = f"{soar_base_url}/rest/handler/phantom_soar_mcp_server/mcp"
    else:
        mcp_endpoint = "https://YOUR_SOAR_HOST/rest/handler/phantom_soar_mcp_server/mcp"

    # Compute read vs write breakdown using known write tool names
    write_enabled_count = len([t for t in enabled_tools if t in _WRITE_TOOLS])
    read_count = len(enabled_tools) - write_enabled_count

    # --- Build Claude Desktop JSON ---
    claude_desktop_config = {
        "mcpServers": {
            "splunk-soar": {
                "url": mcp_endpoint,
                "headers": {
                    "ph-auth-token": "YOUR_SOAR_AUTH_TOKEN"
                }
            }
        }
    }

    # --- Build Claude Code JSON (~/.claude.json snippet) ---
    claude_code_config = {
        "mcpServers": {
            "splunk-soar": {
                "type": "http",
                "url": mcp_endpoint,
                "headers": {
                    "ph-auth-token": "YOUR_SOAR_AUTH_TOKEN"
                }
            }
        }
    }

    # --- Claude Code CLI command ---
    cli_command = (
        f'claude mcp add splunk-soar \\\n'
        f'  --transport http \\\n'
        f'  --url "{mcp_endpoint}" \\\n'
        f'  --header "ph-auth-token: YOUR_SOAR_AUTH_TOKEN"'
    )

    return {
        "status": status,
        "message": message,
        "mcp_endpoint": mcp_endpoint,
        "server_name": server_name,
        "server_version": server_version,
        "protocol_version": protocol_version,
        "enabled_tools": sorted(enabled_tools) if enabled_tools else [],
        "disabled_tools": sorted(disabled_tools) if disabled_tools else [],
        "enabled_count": len(enabled_tools),
        "read_count": read_count,
        "write_count": write_enabled_count,
        "max_results": max_results,
        "ssl_verify": ssl_verify,
        "log_tool_calls": log_tool_calls,
        "advisory_disclaimer": advisory_disclaimer,
        "min_severity": min_severity,
        "max_items_per_case": max_items_per_case,
        "claude_desktop_json": json.dumps(claude_desktop_config, indent=2),
        "claude_code_json": json.dumps(claude_code_config, indent=2),
        "claude_code_cli": cli_command,
    }
