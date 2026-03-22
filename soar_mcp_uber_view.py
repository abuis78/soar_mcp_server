#!/usr/bin/env python3
"""
SOAR MCP Server — Uber View (Case Widget)
Copyright 2026 Andreas Buis
"""

import json
import traceback as _tb

_WRITE_TOOLS = frozenset([
    "add_case_note", "run_playbook", "update_case_status",
    "update_case_severity", "update_case_owner", "create_artifact",
])

_DEFAULT_ENABLED = [
    "list_cases", "get_case", "search_cases", "list_artifacts",
    "get_artifact", "list_case_notes", "list_playbooks",
    "get_playbook_run", "list_action_runs", "list_users", "get_soar_info",
]

_ALL_TOOLS = _DEFAULT_ENABLED + list(_WRITE_TOOLS)


def display_uber_view(provides, all_app_runs, context):
    """Case-level widget. Catches all errors and surfaces them in the HTML."""
    try:
        soar_base = _get_base_url(context)
        data = _find_config_data(all_app_runs)
        has_data = bool(data)

        endpoint = (
            data.get("mcp_endpoint")
            or (soar_base + "/rest/handler/phantom_soar_mcp_server/mcp" if soar_base else "")
            or "https://YOUR_SOAR_HOST/rest/handler/phantom_soar_mcp_server/mcp"
        )

        enabled = list(data.get("enabled_tools", _DEFAULT_ENABLED))
        disabled = list(data.get("disabled_tools",
                                  [t for t in _ALL_TOOLS if t not in enabled]))

        desktop_json = json.dumps({"mcpServers": {"splunk-soar": {
            "url": endpoint,
            "headers": {"ph-auth-token": "YOUR_SOAR_AUTH_TOKEN"}
        }}}, indent=2)

        code_json = json.dumps({"mcpServers": {"splunk-soar": {
            "type": "http",
            "url": endpoint,
            "headers": {"ph-auth-token": "YOUR_SOAR_AUTH_TOKEN"}
        }}}, indent=2)

        cli = (
            "claude mcp add splunk-soar \\\n"
            "  --transport http \\\n"
            "  --url \"" + endpoint + "\" \\\n"
            "  --header \"ph-auth-token: YOUR_SOAR_AUTH_TOKEN\""
        )

        # Build tool pill HTML entirely in Python — no Jinja2 logic needed
        def pill(t, kind):
            colors = {
                "read":  ("background:#0e1c30;color:#5090c8;border:1px solid #1a3050;",),
                "write": ("background:#201808;color:#c08030;border:1px solid #503010;",),
                "off":   ("background:#1a1c20;color:#444850;border:1px solid #2e3138;",),
            }
            st = colors[kind][0]
            return ('<span style="font-family:monospace;font-size:10px;padding:2px 7px;'
                    'border-radius:3px;' + st + '">' + t + '</span>')

        enabled_pills = " ".join(
            pill(t, "write" if t in _WRITE_TOOLS else "read")
            for t in sorted(enabled)
        )
        disabled_pills = " ".join(pill(t, "off") for t in sorted(disabled))

        context.update({
            "error_html": "",
            "notice_html": "" if has_data else (
                '<div style="background:#1a1a10;border:1px solid #504020;border-radius:4px;'
                'padding:7px 10px;font-size:11px;color:#a09040;margin-bottom:12px;">'
                'ℹ Showing default config. Run <strong>Get MCP Config</strong> '
                'via the ACTION button for live values.</div>'
            ),
            "endpoint": endpoint,
            "server_version": data.get("server_version", "1.2.0"),
            "enabled_count": str(len(enabled)),
            "read_count": str(len([t for t in enabled if t not in _WRITE_TOOLS])),
            "write_count": str(len([t for t in enabled if t in _WRITE_TOOLS])),
            "max_results": str(data.get("max_results", 50)),
            "max_items": str(data.get("max_items_per_case", 200)),
            "min_sev": str(data.get("min_severity", "") or "all"),
            "ssl_verify": str(data.get("ssl_verify", True)),
            "log_tools": str(data.get("log_tool_calls", True)),
            "protocol": data.get("protocol_version", "2024-11-05"),
            "desktop_json": desktop_json,
            "code_json": code_json,
            "cli_cmd": cli,
            "enabled_pills": enabled_pills,
            "disabled_pills": disabled_pills,
            "disabled_count": str(len(disabled)),
        })

    except Exception:
        err = _tb.format_exc()
        try:
            open("/tmp/mcp_uber_err.txt", "w").write(err)
        except Exception:
            pass
        context.update({
            "error_html": (
                '<div style="background:#1a0000;border:1px solid #600;border-radius:4px;'
                'padding:10px;margin-bottom:10px;">'
                '<b style="color:#f66;">Widget error:</b>'
                '<pre style="color:#f99;font-size:10px;white-space:pre-wrap;">'
                + err.replace("<", "&lt;").replace(">", "&gt;") +
                '</pre></div>'
            ),
            "notice_html": "", "endpoint": "", "server_version": "",
            "enabled_count": "0", "read_count": "0", "write_count": "0",
            "max_results": "50", "max_items": "200", "min_sev": "all",
            "ssl_verify": "True", "log_tools": "True", "protocol": "",
            "desktop_json": "", "code_json": "", "cli_cmd": "",
            "enabled_pills": "", "disabled_pills": "", "disabled_count": "0",
        })

    return "soar_mcp_uber_view.html"


def _get_base_url(context):
    """
    Try every known method to get the SOAR base URL, in order of preference.
    Writes debug info to /tmp/mcp_base_url_debug.txt on the first call.
    """
    attempts = []

    # 1. SOAR's own helper (most reliable)
    try:
        import phantom.rest as _pr
        url = _pr.get_phantom_base_url()
        if url:
            attempts.append(("phantom.rest", url))
            _write_debug(attempts)
            return url.rstrip("/")
    except Exception as e:
        attempts.append(("phantom.rest", "err: " + str(e)))

    req = context.get("request")
    if req:
        # 2. build_absolute_uri handles reverse-proxy headers automatically
        try:
            url = req.build_absolute_uri("/").rstrip("/")
            if url and "YOUR_SOAR" not in url:
                attempts.append(("build_absolute_uri", url))
                _write_debug(attempts)
                return url
        except Exception as e:
            attempts.append(("build_absolute_uri", "err: " + str(e)))

        # 3. Forwarded host header (set by reverse proxy)
        try:
            meta = getattr(req, "META", {})
            fwd = meta.get("HTTP_X_FORWARDED_HOST") or meta.get("HTTP_X_FORWARDED_SERVER")
            proto = meta.get("HTTP_X_FORWARDED_PROTO", "https")
            if fwd:
                url = proto + "://" + fwd
                attempts.append(("x-forwarded-host", url))
                _write_debug(attempts)
                return url
        except Exception as e:
            attempts.append(("x-forwarded-host", "err: " + str(e)))

        # 4. Standard Django HOST header
        try:
            host = req.get_host()
            scheme = getattr(req, "scheme", "https")
            url = scheme + "://" + host
            if host:
                attempts.append(("get_host", url))
                _write_debug(attempts)
                return url
        except Exception as e:
            attempts.append(("get_host", "err: " + str(e)))

        # 5. Dump META keys for debugging
        try:
            meta = getattr(req, "META", {})
            attempts.append(("META_keys", str(sorted([k for k in meta if "HOST" in k or "SERVER" in k or "FORWARD" in k]))))
        except Exception:
            pass

    _write_debug(attempts)
    return ""


def _write_debug(info):
    try:
        with open("/tmp/mcp_base_url_debug.txt", "w") as f:
            for k, v in info:
                f.write(k + ": " + str(v) + "\n")
    except Exception:
        pass


def _find_config_data(all_app_runs):
    try:
        runs = list(all_app_runs or [])
        for run in reversed(runs):
            try:
                action_results = run[1] if len(run) >= 2 else []
                for r in (action_results or []):
                    if not isinstance(r, dict):
                        continue
                    if r.get("status") != "success":
                        continue
                    if "config" not in (r.get("message") or "").lower():
                        continue
                    d = r.get("data", [])
                    if d and isinstance(d, list):
                        return d[0]
            except Exception:
                continue
    except Exception:
        pass
    return {}
