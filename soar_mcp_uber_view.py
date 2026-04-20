#!/usr/bin/env python3
"""
SOAR MCP Server — Uber View (Case Widget)
Copyright 2026 Andreas Buis
"""

import json
import os
import traceback as _tb

_WRITE_TOOLS = frozenset([
    "add_case_note", "run_playbook", "update_case_status",
    "update_case_severity", "update_case_owner", "create_artifact",
])

# Handler URL constants (must match soar_mcp_handler.py)
_APPID = "ff5f68f3-353c-4d89-9767-967ef5d99117"
_HANDLER_DIR = f"soarmcpserver_{_APPID}"

_DEFAULT_ENABLED = [
    "list_cases", "get_case", "search_cases", "list_artifacts",
    "get_artifact", "list_case_notes", "list_playbooks",
    "get_playbook_run", "list_action_runs", "list_users", "get_soar_info",
]

_ALL_TOOLS = _DEFAULT_ENABLED + list(_WRITE_TOOLS)


def display_uber_view(provides, all_app_runs, context):
    """Case-level widget. Catches all errors and surfaces them in the HTML."""
    try:
        # ── 1. Gather all available data sources ──────────────────────────────
        overrides = _read_asset_overrides()
        data = _find_config_data(all_app_runs)

        # ── 2. Base URL — prefer phantom.rest system setting (always accurate) ─
        soar_base = (
            _get_base_url(context)          # phantom.rest.get_phantom_base_url()
            or overrides.get("base_url", "")
            or data.get("base_url", "")
        ).rstrip("/")

        # ── 3. Asset name — try every available source ────────────────────────
        asset_name = (
            _extract_asset_name_from_provides(provides)
            or overrides.get("asset_name", "")
            or data.get("asset_name", "")
            or _extract_asset_name_from_runs(all_app_runs)
            or _extract_asset_name_from_request(context)
        )
        # Write debug info so we can see what SOAR passes
        _write_provides_debug(provides, asset_name, context)

        # ── 4. Build endpoint — always fresh from soar_base + asset_name ──────
        # Never use the stored mcp_endpoint from overrides because the
        # connector may have written it before the base_url was known.
        if soar_base and asset_name:
            endpoint = f"{soar_base}/rest/handler/{_HANDLER_DIR}/{asset_name}"
        elif soar_base:
            endpoint = f"{soar_base}/rest/handler/{_HANDLER_DIR}/YOUR_ASSET_NAME"
        elif asset_name:
            endpoint = f"https://YOUR_SOAR_HOST/rest/handler/{_HANDLER_DIR}/{asset_name}"
        else:
            endpoint = f"https://YOUR_SOAR_HOST/rest/handler/{_HANDLER_DIR}/YOUR_ASSET_NAME"

        # ── 5. Auth token ─────────────────────────────────────────────────────
        auth_token = (
            overrides.get("auth_token")
            or data.get("auth_token")
            or "YOUR_SOAR_AUTH_TOKEN"
        )

        # ── 6. Has live data? ─────────────────────────────────────────────────
        has_data = bool(soar_base and asset_name and auth_token != "YOUR_SOAR_AUTH_TOKEN")

        enabled = list(data.get("enabled_tools", _DEFAULT_ENABLED))
        disabled = list(data.get("disabled_tools",
                                  [t for t in _ALL_TOOLS if t not in enabled]))

        desktop_json = json.dumps({"mcpServers": {"splunk-soar": {
            "url": endpoint,
            "headers": {"ph-auth-token": auth_token}
        }}}, indent=2)

        code_json = json.dumps({"mcpServers": {"splunk-soar": {
            "type": "http",
            "url": endpoint,
            "headers": {"ph-auth-token": auth_token}
        }}}, indent=2)

        # Correct syntax per `claude mcp add --help`:
        #   claude mcp add [options] <name> <url> [options-after-url]
        # --transport goes before name; -H (header) goes after url.
        cli = (
            "claude mcp add \\\n"
            "  --transport http \\\n"
            "  splunk-soar \\\n"
            "  \"" + endpoint + "\" \\\n"
            "  -H \"ph-auth-token: " + auth_token + "\""
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
                'ℹ Showing default config. Run <strong>Test Connectivity</strong> '
                'on the asset to populate with live values.</div>'
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


def _write_provides_debug(provides, resolved_name: str, context) -> None:
    """Write debug info to /tmp so the asset_name source can be diagnosed."""
    try:
        req = context.get("request")
        path = getattr(req, "path", "") if req else ""
        meta_keys = sorted([k for k in (getattr(req, "META", {}) or {}) if any(
            x in k for x in ("HOST", "PATH", "FORWARD", "USER", "ASSET"))]) if req else []
        with open("/tmp/mcp_asset_debug.txt", "w") as f:
            f.write(f"provides type: {type(provides)}\n")
            f.write(f"provides repr: {repr(provides)}\n")
            f.write(f"resolved asset_name: {resolved_name}\n")
            f.write(f"request.path: {path}\n")
            f.write(f"META keys (filtered): {meta_keys}\n")
            # Try to show dir() of provides for unknown types
            try:
                f.write(f"provides dir: {[x for x in dir(provides) if not x.startswith('__')]}\n")
            except Exception:
                pass
    except Exception:
        pass


def _extract_asset_name_from_runs(all_app_runs) -> str:
    """
    Try to extract the asset name from the all_app_runs summary dict.
    SOAR sometimes includes asset_name in the run summary.
    """
    try:
        for run in (all_app_runs or []):
            summary = run[0] if run and len(run) >= 1 else {}
            if isinstance(summary, dict):
                name = summary.get("asset_name") or summary.get("asset") or ""
                if name and isinstance(name, str):
                    return name.strip()
    except Exception:
        pass
    return ""


def _extract_asset_name_from_provides(provides) -> str:
    """
    Extract the asset name from the `provides` argument of the uber_view.

    In SOAR, `provides` for an asset uber_view is the asset name string,
    or occasionally a dict/object with a 'name' key.
    """
    try:
        if isinstance(provides, str) and provides:
            return provides.strip()
        if isinstance(provides, dict):
            return str(provides.get("name") or provides.get("asset_name") or "").strip()
        # Some SOAR versions pass an object
        name = getattr(provides, "name", None) or getattr(provides, "asset_name", None)
        if name:
            return str(name).strip()
    except Exception:
        pass
    return ""


def _extract_asset_name_from_request(context) -> str:
    """
    Try to extract the asset name from the Django request URL path.

    SOAR asset pages are typically at /asset/<asset_name>/... or
    /assets/<asset_name>/...
    """
    try:
        req = context.get("request")
        if not req:
            return ""
        path = getattr(req, "path", "") or ""
        parts = [p for p in path.split("/") if p]
        for keyword in ("asset", "assets"):
            if keyword in parts:
                idx = parts.index(keyword)
                if idx + 1 < len(parts):
                    candidate = parts[idx + 1]
                    # Exclude numeric IDs and generic words
                    if candidate and not candidate.isdigit() and candidate not in ("overview", "edit", "summary"):
                        return candidate
    except Exception:
        pass
    return ""


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


def _read_asset_overrides() -> dict:
    """
    Read asset_overrides.json written by the connector (on Test Connectivity /
    any action) and updated by the REST handler (on first MCP request).

    Returns an empty dict if the file does not exist or cannot be parsed.
    """
    try:
        app_dir = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(app_dir, "local", "asset_overrides.json")
        if not os.path.exists(path):
            return {}
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def _find_config_data(all_app_runs):
    try:
        runs = list(all_app_runs or [])
        for run in reversed(runs):
            try:
                action_results = run[1] if len(run) >= 2 else []
                for r in (action_results or []):
                    try:
                        # ActionResult objects use get_status() / get_data() / get_message()
                        if hasattr(r, "get_status"):
                            if r.get_status() != "success":
                                continue
                            msg = (r.get_message() or "") if hasattr(r, "get_message") else ""
                            if "config" not in msg.lower():
                                continue
                            d = r.get_data() if hasattr(r, "get_data") else []
                            if d and isinstance(d, list):
                                return d[0]
                        # Fallback: plain dict (local test / older SOAR versions)
                        elif isinstance(r, dict):
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
                continue
    except Exception:
        pass
    return {}
