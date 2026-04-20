#!/usr/bin/env python3
"""
SOAR MCP Server — BaseConnector

This connector handles the standard SOAR app actions (test connectivity,
get config). The actual MCP server functionality is provided by the REST
handler registered as 'rest_handler' in soar_mcp_server.json.

Copyright 2026 Andreas Buis
"""

import json
import os
import sys

import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

_app_dir = os.path.dirname(os.path.abspath(__file__))
if _app_dir not in sys.path:
    sys.path.insert(0, _app_dir)

from soar_mcp_config import ALL_TOOLS, READ_ONLY_TOOLS, McpConfigLoader, get_config
from soar_mcp_handler import build_mcp_endpoint


class SoarMcpConnector(BaseConnector):
    """
    Standard SOAR connector for the SOAR MCP Server app.

    This connector provides health-check and configuration-inspection actions.
    The MCP protocol handling is done entirely by SoarMcpRestHandler in
    soar_mcp_handler.py — this connector does NOT handle MCP directly.
    """

    def __init__(self) -> None:
        super().__init__()
        self._base_url: str = ""
        self._auth_token: str = ""

    def initialize(self) -> bool:
        asset_cfg = self.get_config()
        # Asset config field is used for Test Connectivity; fall back to the
        # SOAR system base URL (Administration → Company Settings → Base URL).
        self._base_url = (
            (asset_cfg.get("base_url") or "").strip().rstrip("/")
            or self._get_soar_base_url()
        )
        self._auth_token = (asset_cfg.get("auth_token") or "").strip()
        self._asset_name = self._get_asset_name()
        # Sync asset config checkboxes → local/asset_overrides.json so the
        # REST handler picks up any tool enable/disable changes immediately.
        self._write_asset_overrides(asset_cfg)
        return phantom.APP_SUCCESS

    def _get_soar_base_url(self) -> str:
        """Return the SOAR system base URL from Administration → Company Settings."""
        try:
            import phantom.rest as _pr
            url = _pr.get_phantom_base_url()
            if url:
                return url.strip().rstrip("/")
        except Exception:
            pass
        return ""

    def _get_asset_name(self) -> str:
        """Return the SOAR asset name for this connector instance."""
        # Method 1: SOAR SDK method (newer SDK versions)
        try:
            name = self.get_asset_name()
            if name:
                return str(name)
        except Exception:
            pass

        # Method 2: Internal connector info dict
        try:
            info = getattr(self, "_connector_info", {}) or {}
            name = info.get("asset_name") or info.get("name") or ""
            if name:
                return str(name)
        except Exception:
            pass

        # Method 3: Internal _connector dict (used by some SOAR versions)
        try:
            conn = getattr(self, "_connector", {}) or {}
            name = conn.get("asset_name") or conn.get("name") or ""
            if name:
                return str(name)
        except Exception:
            pass

        # Method 4: Query SOAR REST API via asset_id (most reliable fallback)
        try:
            asset_id = self.get_asset_id()
            if asset_id and self._base_url and self._auth_token:
                import requests as _req
                resp = _req.get(
                    f"{self._base_url}/rest/asset/{asset_id}",
                    headers={"ph-auth-token": self._auth_token},
                    verify=False,
                    timeout=10,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    name = data.get("name") or data.get("asset_name") or ""
                    if name:
                        return str(name)
        except Exception:
            pass

        return ""

    def _write_asset_overrides(self, asset_cfg: dict) -> None:
        """
        Read tool checkboxes and AI instructions from the SOAR asset config
        and persist them to local/asset_overrides.json.

        The REST handler calls get_config(reload=True) on each request,
        which reads this file and applies it on top of mcp.conf.

        Logic per tool:
          - asset_cfg has True  → explicitly enabled
          - asset_cfg has False → explicitly disabled
          - asset_cfg is None / key absent → use the built-in default
            (read tools ON, write tools OFF)
        """
        tool_overrides: dict = {}
        for tool in ALL_TOOLS:
            val = asset_cfg.get(f"tool_{tool}")
            if val is True:
                tool_overrides[tool] = True
            elif val is False:
                tool_overrides[tool] = False
            else:
                # Key absent or None → use built-in default
                tool_overrides[tool] = (tool in READ_ONLY_TOOLS)

        ai_instructions = (asset_cfg.get("ai_instructions") or "").strip()

        # Build the correct MCP endpoint URL (base_url is from asset config for
        # test connectivity; the real base_url is also detected by the handler
        # from the incoming request and will overwrite this on first MCP call).
        mcp_endpoint = ""
        if self._base_url and self._asset_name:
            mcp_endpoint = build_mcp_endpoint(self._base_url, self._asset_name)

        overrides = {
            "tools": tool_overrides,
            "ai_instructions": ai_instructions,
            "asset_name": self._asset_name,
            "base_url": self._base_url,
            "auth_token": self._auth_token,
            "mcp_endpoint": mcp_endpoint,
        }

        app_dir = os.path.dirname(os.path.abspath(__file__))
        local_dir = os.path.join(app_dir, "local")
        try:
            os.makedirs(local_dir, exist_ok=True)
            overrides_path = os.path.join(local_dir, "asset_overrides.json")
            with open(overrides_path, "w", encoding="utf-8") as fh:
                json.dump(overrides, fh, indent=2)
            self.debug_print(
                f"[MCP] Asset overrides written: "
                f"{sum(1 for v in tool_overrides.values() if v)} tools enabled"
            )
        except Exception as exc:
            self.debug_print(f"[MCP] Warning: could not write asset_overrides.json: {exc}")

        # Invalidate the config cache so this process also sees the new values
        get_config(reload=True)

    def finalize(self) -> bool:
        return phantom.APP_SUCCESS

    def handle_action(self, param: dict) -> bool:
        action_id = self.get_action_identifier()
        dispatch = {
            "test_connectivity": self._handle_test_connectivity,
            "get_mcp_config": self._handle_get_mcp_config,
        }
        handler = dispatch.get(action_id)
        if handler:
            return handler(param)
        return self.set_status(phantom.APP_ERROR, f"Unknown action: {action_id}")

    def _handle_test_connectivity(self, param: dict) -> bool:
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Applying asset configuration...")

        # get_config(reload=True) re-reads mcp.conf + asset_overrides.json
        # (asset_overrides.json was written by initialize() above)
        config = get_config(reload=True)
        self.save_progress(f"Config loaded. {len(config.enabled_tools)} tools enabled.")

        # Build expected MCP endpoint URL using the correct SOAR handler path
        soar_host = self._base_url or "https://<this-soar-instance>"
        asset = self._asset_name or "<asset_name>"
        mcp_endpoint = build_mcp_endpoint(soar_host, asset)

        # If a base_url and token are configured, do a quick SOAR API health check
        if self._base_url and self._auth_token:
            try:
                import requests

                resp = requests.get(
                    f"{self._base_url}/rest/version",
                    headers={"ph-auth-token": self._auth_token},
                    verify=config.ssl_verify,
                    timeout=15,
                )
                if resp.status_code == 401:
                    return action_result.set_status(
                        phantom.APP_ERROR,
                        "SOAR API authentication failed (HTTP 401). Check auth_token.",
                    )
                if resp.status_code == 200:
                    version_info = resp.json()
                    self.save_progress(f"SOAR version: {version_info.get('version', 'unknown')}")
                else:
                    self.save_progress(f"SOAR API returned HTTP {resp.status_code} — check base_url.")
            except Exception as exc:
                self.save_progress(f"SOAR API check failed: {exc} — verifying config only.")

        action_result.add_data({
            "mcp_endpoint": mcp_endpoint,
            "enabled_tools": sorted(config.enabled_tools),
            "config_summary": config.to_summary_dict(),
        })
        action_result.set_summary({
            "mcp_endpoint": mcp_endpoint,
            "enabled_tools": len(config.enabled_tools),
            "write_tools_enabled": config.write_tools_enabled,
        })
        return action_result.set_status(
            phantom.APP_SUCCESS,
            f"SOAR MCP Server configured. Endpoint: {mcp_endpoint}",
        )

    def _handle_get_mcp_config(self, param: dict) -> bool:
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Loading mcp.conf...")

        config = get_config(reload=True)
        summary = config.to_summary_dict()

        soar_host = self._base_url or "https://<this-soar-instance>"
        asset = self._asset_name or "<asset_name>"
        mcp_endpoint = build_mcp_endpoint(soar_host, asset)

        # Include connection details so the widget can render copy-ready config
        summary["mcp_endpoint"] = mcp_endpoint
        summary["base_url"] = self._base_url
        summary["auth_token"] = self._auth_token

        action_result.add_data(summary)
        action_result.set_summary({
            "enabled_tools": len(config.enabled_tools),
            "write_tools_enabled": config.write_tools_enabled,
            "max_results": config.max_results,
        })
        return action_result.set_status(phantom.APP_SUCCESS, "MCP config loaded successfully.")


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as fh:
        in_json = fh.read()
    parsed = json.loads(in_json)
    print(json.dumps(parsed, indent=4))
    connector = SoarMcpConnector()
    connector.print_progress_message = True
    ret_val = connector._handle_action(in_json, None)
    print(json.dumps(json.loads(ret_val), indent=4))
    sys.exit(0)
