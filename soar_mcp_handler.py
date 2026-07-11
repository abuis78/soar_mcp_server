"""
SOAR MCP Server — MCP REST Handler
Copyright 2026 Andreas Buis

SOAR Django REST handler pattern (discovered via v1.4.14 diagnostics):
  - SOAR calls SoarMcpRestHandler(django_request, path_args) — request in __init__!
  - SOAR does json.dumps(handler_instance) as the HTTP response body
  - handle() is never called; all logic goes in __init__ (or called from it)
  - Handler must be a dict subclass so json.dumps() works

Request:
  args[0]  = django.core.handlers.wsgi.WSGIRequest
  args[1]  = list of URL path segments, e.g. ['mcp2']

Response:
  self (dict) is serialised by SOAR as the HTTP response body (JSON)
  HTTP status is always 200 from SOAR's side; use JSON-RPC errors for failures
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys

# ── App directory on sys.path ──────────────────────────────────────────────────
_app_dir = os.path.dirname(os.path.abspath(__file__))
if _app_dir not in sys.path:
    sys.path.insert(0, _app_dir)

from soar_mcp_config import McpServerConfig, get_config
from soar_mcp_tools import TOOL_SCHEMAS, SoarApiClient, call_tool
from soar_mcp_utils import redact_nested

try:
    from soar_mcp_tokens import TokenStore, TokenVerification, sanitise_args_for_audit
except Exception:  # noqa: BLE001
    TokenStore = None  # type: ignore[misc,assignment]
    TokenVerification = None  # type: ignore[misc,assignment]

    def sanitise_args_for_audit(args: dict) -> dict:  # type: ignore[no-redef]
        """Return a copy of args safe for audit logging: sensitive values redacted, strings truncated."""
        try:
            return redact_nested(args)
        except Exception:
            return {"_redaction_error": "sanitisation failed"}

import hashlib

# Rate limiter for the legacy ph-auth-token path (issue #44). Scoped tokens are
# rate-limited inside the token store; without this the default legacy path is
# unbounded. Per-process only — use a reverse-proxy limit for a hard DoS ceiling.
try:
    from soar_mcp_tokens import _RateLimiter as _LegacyRateLimiter
    _legacy_rate_limiter = _LegacyRateLimiter()
except Exception:  # noqa: BLE001
    _legacy_rate_limiter = None

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("soar_mcp.audit")

# ── Handler URL constants ──────────────────────────────────────────────────────
_APPID = "ff5f68f3-353c-4d89-9767-967ef5d99117"
_HANDLER_DIR = f"soarmcpserver_{_APPID}"

_JSONRPC_PARSE_ERROR      = -32700
_JSONRPC_INVALID_REQUEST  = -32600
_JSONRPC_METHOD_NOT_FOUND = -32601
_JSONRPC_INVALID_PARAMS   = -32602
_JSONRPC_INTERNAL_ERROR   = -32603


class _InvalidParamsError(Exception):
    """Raised when a JSON-RPC call has invalid or missing parameters (maps to -32602)."""


def build_mcp_endpoint(base_url: str, asset_name: str) -> str:
    return f"{base_url.rstrip('/')}/rest/handler/{_HANDLER_DIR}/{asset_name}"


# ── SOAR Django REST handler ───────────────────────────────────────────────────

class SoarMcpRestHandler(dict):
    """
    SOAR REST handler for the MCP server.

    SOAR's Django framework passes the WSGIRequest to __init__ and
    serialises this dict instance as the HTTP response body.
    All request processing happens in __init__ (via _process).
    """

    def __init__(self, request=None, path_args=None, *args, **kwargs):
        super().__init__()
        try:
            response = self._process(request, path_args or [])
        except Exception as exc:
            # Detail is logged server-side only; never echoed to the client (#57).
            logger.exception("[SOAR MCP] Fatal error in __init__: %s", exc)
            response = self._error(None, _JSONRPC_INTERNAL_ERROR,
                                   "Internal MCP handler error.")
        self.update(response)

    # ── Request processing ─────────────────────────────────────────────────────

    def _process(self, request, path_args: list) -> dict:
        # Load config (tool enable/disable, AI instructions)
        try:
            config = get_config(reload=True)
        except Exception:
            config = McpServerConfig()

        # Extract HTTP method
        method = getattr(request, "method", "POST").upper() if request else "POST"

        # Extract auth token from Django META.
        #
        # SOAR's outer Django auth layer authenticates requests *before* they
        # reach this handler. In practice it only honours `ph-auth-token`;
        # `Authorization: Bearer <token>` is rejected upstream with
        # "Invalid JWT" and never gets here, so the previous Bearer fallback
        # was dead code. We still read both keys so a future SOAR release
        # (or a reverse proxy that rewrites headers) can pass either form.
        meta = getattr(request, "META", {}) or {}
        auth_token = (
            meta.get("HTTP_PH_AUTH_TOKEN", "")
            or meta.get("HTTP_AUTHORIZATION", "").replace("Bearer ", "").strip()
        ).strip()

        # Cursor / Streamable HTTP MCP clients may send Mcp-Session-Id;
        # we don't track sessions server-side but accept and ignore it.
        session_id = meta.get("HTTP_MCP_SESSION_ID", "")

        # Extract base URL from request for API callbacks
        soar_base = self._extract_base_url(request, config)

        # Persist asset name for widget
        asset_name = path_args[0] if path_args else ""
        if asset_name and soar_base:
            self._persist_endpoint(soar_base, asset_name)

        # Handle GET (SSE endpoint — return minimal SSE compatible response)
        if method == "GET":
            # SOAR serialises this dict as body; wrap SSE-like response in JSON
            return {"event": "endpoint", "data": {}}

        # Handle OPTIONS (CORS preflight)
        if method == "OPTIONS":
            return {}

        # Parse request body
        body_bytes = b""
        if request is not None:
            try:
                body_bytes = request.body  # bytes in Django
            except Exception:
                pass

        if not body_bytes:
            return self._error(None, _JSONRPC_PARSE_ERROR, "Empty request body")

        # Parse JSON-RPC
        try:
            rpc = json.loads(body_bytes)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.info("[SOAR MCP] JSON parse error: %s", exc)
            return self._error(None, _JSONRPC_PARSE_ERROR, "Invalid JSON in request body.")

        if not isinstance(rpc, dict):
            return self._error(None, _JSONRPC_INVALID_REQUEST, "Request must be a JSON object")

        rpc_id     = rpc.get("id")
        rpc_method = rpc.get("method", "")
        params     = rpc.get("params") or {}

        logger.info("[SOAR MCP] %s (id=%s)", rpc_method, rpc_id)

        # Require auth for all methods except initialize/notifications/ping
        if not auth_token:
            return self._error(rpc_id, -32000,
                "Missing ph-auth-token header. Add it to your MCP client configuration.")

        # Resolve auth: scoped MCP token (preferred) or legacy SOAR ph-auth-token.
        # Scoped tokens are looked up in the app's local token store; if found,
        # the bound SOAR service token is used to call the SOAR API and tool
        # access is further restricted to the scoped allow-list.
        token_verification = None
        soar_call_token = auth_token
        if TokenStore is not None and config.scoped_tokens_enabled:
            try:
                store = TokenStore.default()
                token_verification = store.verify(
                    auth_token,
                    rate_limit=config.token_rate_limit_per_minute,
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception("[SOAR MCP] Token store error: %s", exc)
                token_verification = None

            if token_verification is not None:
                if not token_verification.valid:
                    audit_logger.warning(
                        "[SOAR MCP] auth=reject reason=%s rpc_method=%s",
                        token_verification.reason, rpc_method,
                    )
                    return self._error(rpc_id, -32000,
                        f"MCP token rejected: {token_verification.reason}")
                soar_call_token = token_verification.soar_call_token or auth_token

        if token_verification is None and config.scoped_tokens_required:
            audit_logger.warning(
                "[SOAR MCP] auth=reject reason=legacy_token_blocked rpc_method=%s",
                rpc_method,
            )
            return self._error(rpc_id, -32000,
                "This SOAR MCP instance requires a scoped MCP token. "
                "Ask a SOAR admin to mint one with the 'mint mcp token' action.")

        if token_verification is None and config.legacy_full_token_warn:
            logger.info("[SOAR MCP] Legacy full ph-auth-token used (rpc_method=%s)", rpc_method)

        # Rate-limit the legacy ph-auth-token path too (#44). Keyed on a hash of
        # the presented token so the raw token is never used as a dict key.
        if (token_verification is None
                and _legacy_rate_limiter is not None
                and config.token_rate_limit_per_minute > 0):
            legacy_key = "legacy:" + hashlib.sha256(auth_token.encode()).hexdigest()[:16]
            if not _legacy_rate_limiter.check(legacy_key, config.token_rate_limit_per_minute):
                audit_logger.warning(
                    "[SOAR MCP] auth=reject reason=rate_limited path=legacy rpc_method=%s",
                    rpc_method,
                )
                return self._error(rpc_id, -32000, "Rate limit exceeded. Try again shortly.")

        # Tool calls need a usable base URL. Fail with a clear, actionable error
        # rather than letting a scheme-less/empty base_url produce opaque
        # "MissingSchema" errors deep in every tool (base_url regression).
        if rpc_method == "tools/call" and not soar_base:
            return self._error(rpc_id, _JSONRPC_INTERNAL_ERROR,
                "Could not determine the SOAR base URL. Set 'base_url' in the SOAR "
                "MCP Server asset configuration and run Test Connectivity.")

        # Build SOAR API client for tool calls
        client = SoarApiClient(soar_base, soar_call_token, config)

        # Dispatch JSON-RPC method
        try:
            if rpc_method == "initialize":
                result = self._handle_initialize(params, config)
            elif rpc_method == "notifications/initialized":
                return {}   # Notification — empty response is correct
            elif rpc_method == "tools/list":
                result = self._handle_tools_list(config, token_verification)
            elif rpc_method == "tools/call":
                result = self._handle_tools_call(
                    params, client, config, token_verification,
                )
            elif rpc_method == "ping":
                result = {}
            else:
                return self._error(rpc_id, _JSONRPC_METHOD_NOT_FOUND,
                                   f"Method not found: {rpc_method}")
        except _InvalidParamsError as exc:
            # Fix #12: return -32602 Invalid Params for bad tool call arguments
            return self._error(rpc_id, _JSONRPC_INVALID_PARAMS, str(exc))
        except Exception as exc:
            logger.exception("[SOAR MCP] Error in method %s: %s", rpc_method, exc)
            return self._error(rpc_id, _JSONRPC_INTERNAL_ERROR, "Internal server error")

        return {"jsonrpc": "2.0", "id": rpc_id, "result": result}

    # ── MCP method implementations ─────────────────────────────────────────────

    def _handle_initialize(self, params: dict, config: McpServerConfig) -> dict:
        base = (
            "You are connected to a Splunk SOAR (Security Orchestration, Automation & Response) "
            "instance via the Model Context Protocol.\n\n"
            "SOAR manages incidents ('cases'), IOC observables ('artifacts'), analyst notes, "
            "and automated response playbooks.\n\n"
            "How to work effectively:\n"
            "- Start with list_cases or search_cases to find relevant incidents.\n"
            "- Use get_case for full case details (status, severity, owner, description).\n"
            "- Use list_artifacts to see IOCs (IPs, domains, hashes, emails, URLs).\n"
            "- Use list_case_notes to read investigation history and analyst findings.\n"
            "- Use list_playbooks to discover available automated response options.\n"
            "- Severity: high > medium > low > informational.\n"
            "- Status: new, open, in_progress, resolved, closed.\n\n"
            "Write tools (add_case_note, run_playbook, update_case_status, etc.) modify live "
            "SOAR data. Always describe what you plan to do and wait for confirmation before "
            "executing write operations."
        )
        custom = (config.ai_instructions or "").strip()
        instructions = (base + "\n\n--- Environment context ---\n" + custom) if custom else base

        return {
            "protocolVersion": config.protocol_version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": config.server_name, "version": config.server_version},
            "instructions": instructions,
        }

    # Tools whose real function is not yet available on any verified SOAR
    # version, so they must NOT be advertised in tools/list as functional
    # (issue #65). save_playbook_layout_only can only preview (dry_run); its
    # actual write path is blocked until the COA write endpoint is live-verified
    # (see VERIFICATION.md). Hidden from discovery; a direct dry_run call is
    # still honoured by _handle_tools_call for anyone who already knows the name.
    _HIDDEN_FROM_LIST = frozenset({"save_playbook_layout_only"})

    def _handle_tools_list(self, config: McpServerConfig,
                           token_verification=None) -> dict:
        # Scoped token allow-list intersects with asset-config enabled tools.
        allowed = set(config.enabled_tools)
        if token_verification is not None and token_verification.allowed_tools is not None:
            allowed &= set(token_verification.allowed_tools)

        tools = [
            {"name": name, "description": schema["description"],
             "inputSchema": schema["inputSchema"]}
            for name, schema in TOOL_SCHEMAS.items()
            if name in allowed and name not in self._HIDDEN_FROM_LIST
        ]
        logger.info("[SOAR MCP] tools/list → %d tools", len(tools))
        return {"tools": tools}

    def _handle_tools_call(self, params: dict, client: SoarApiClient,
                           config: McpServerConfig,
                           token_verification=None) -> dict:
        tool_name = (params.get("name") or "").strip()
        arguments = params.get("arguments") or {}

        if not tool_name:
            # Return -32602 Invalid Params (not -32603 Internal Server Error) (fix #12)
            raise _InvalidParamsError("tools/call requires a non-empty 'name' parameter")

        safe_layout_preview = (
            tool_name == "save_playbook_layout_only"
            and bool(arguments.get("dry_run", True))
        )
        if tool_name not in config.enabled_tools and not safe_layout_preview:
            if tool_name in TOOL_SCHEMAS:
                text = (f"Tool '{tool_name}' is disabled. Enable it in the SOAR MCP Server "
                        f"asset configuration and run Test Connectivity.")
            else:
                text = f"Unknown tool '{tool_name}'. Call tools/list to see available tools."
            self._audit_tool_call(token_verification, tool_name, arguments,
                                  outcome="denied:disabled")
            return {"content": [{"type": "text", "text": text}], "isError": True}

        if (token_verification is not None
                and token_verification.allowed_tools is not None
                and tool_name not in token_verification.allowed_tools):
            text = (f"Tool '{tool_name}' is not in this MCP token's allow-list. "
                    f"Allowed: {sorted(token_verification.allowed_tools) or 'none'}")
            self._audit_tool_call(token_verification, tool_name, arguments,
                                  outcome="denied:scoped")
            return {"content": [{"type": "text", "text": text}], "isError": True}

        self._audit_tool_call(token_verification, tool_name, arguments, outcome="ok")
        result_text = call_tool(tool_name, arguments, client, config)
        is_error = self._is_tool_error(result_text)
        return {"content": [{"type": "text", "text": result_text}], "isError": is_error}

    @staticmethod
    def _is_tool_error(result_text: str) -> bool:
        """Best-effort MCP isError flag for existing text and structured JSON tool outputs."""
        text = result_text.lstrip()
        if text.startswith(("Error:", "Error ")):
            return True
        try:
            payload = json.loads(text)
        except Exception:
            return False
        if isinstance(payload, dict):
            return payload.get("ok") is False or bool(payload.get("errors"))
        return False

    @staticmethod
    def _audit_tool_call(token_verification, tool_name: str,
                         arguments: dict, *, outcome: str) -> None:
        """Emit a structured audit line. Never logs the token itself."""
        token_id = getattr(token_verification, "token_id", None) if token_verification else None
        label = getattr(token_verification, "label", None) if token_verification else None
        audit_logger.info(
            "[SOAR MCP] tool_call outcome=%s tool=%s token_id=%s label=%s args=%s",
            outcome, tool_name, token_id or "legacy", label or "-",
            json.dumps(sanitise_args_for_audit(arguments), default=str)[:500],
        )

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _error(rpc_id, code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": rpc_id,
                "error": {"code": code, "message": message}}

    @staticmethod
    def _normalize_base_url(url: str) -> str:
        """Return a scheme-qualified base URL, or "" if it can't be made safe.

        Guards against the MissingSchema class of bugs: a scheme-less value
        (e.g. a bare host from some SOAR builds) would otherwise be handed to
        requests and blow up on every API call. Trusted sources missing a
        scheme default to https (never http). Non-http schemes are rejected.
        """
        if not url:
            return ""
        url = url.strip().rstrip("/")
        # Reject embedded credentials (user:pass@host) regardless of scheme (#93).
        host_part = url.split("://", 1)[-1]
        if "@" in host_part.split("/", 1)[0]:
            logger.warning("[SOAR MCP] Ignoring base_url with embedded credentials.")
            return ""
        if re.match(r"^https?://", url, re.I):
            return url
        if "://" not in url:
            return "https://" + url
        return ""

    @staticmethod
    def _read_configured_base_url() -> str:
        """Operator-configured base_url persisted by the connector (asset config).
        Trusted — NOT a request header — so using it does not reintroduce #58."""
        try:
            path = os.path.join(_app_dir, "local", "asset_overrides.json")
            if os.path.exists(path):
                with open(path, encoding="utf-8") as fh:
                    return (json.load(fh).get("base_url") or "").strip()
        except Exception:
            pass
        return ""

    @staticmethod
    def _extract_base_url(request, config=None) -> str:
        # Security (issue #58): the returned base_url is used to build the
        # SoarApiClient that sends the SOAR call token. It must come from a
        # TRUSTED source, NEVER from attacker-controllable request headers
        # (Host / X-Forwarded-*), which could redirect token-bearing API calls
        # to an attacker host (SSRF/credential exfil).
        #
        # Trusted sources, in order (all admin-controlled, never request headers):
        #   1. phantom.rest.get_phantom_base_url() — authoritative on-box.
        #   2. mcp.conf [server] base_url — static admin config, survives across
        #      reinstalls better than local/ (issue #93, contributed by @reisball).
        #   3. asset-config base_url persisted to local/asset_overrides.json by
        #      Test Connectivity.
        # Fail closed ("") if none yields a scheme-qualified URL.
        cls = SoarMcpRestHandler
        try:
            import phantom.rest as _pr
            url = cls._normalize_base_url(_pr.get_phantom_base_url() or "")
            if url:
                return url
        except Exception:
            pass
        if config is not None and getattr(config, "base_url", ""):
            url = cls._normalize_base_url(config.base_url)
            if url:
                return url
        url = cls._normalize_base_url(cls._read_configured_base_url())
        if url:
            return url
        logger.warning("[SOAR MCP] Could not resolve SOAR base URL from phantom.rest, "
                       "mcp.conf, or asset config; refusing to derive it from request headers.")
        return ""

    @staticmethod
    def _persist_endpoint(base_url: str, asset_name: str) -> None:
        try:
            overrides_path = os.path.join(_app_dir, "local", "asset_overrides.json")
            if not os.path.exists(overrides_path):
                return
            with open(overrides_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            endpoint = build_mcp_endpoint(base_url, asset_name)
            if data.get("mcp_endpoint") == endpoint:
                return
            data["mcp_endpoint"] = endpoint
            data["asset_name"]   = asset_name
            data["base_url"]     = base_url
            with open(overrides_path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except Exception:
            pass

    # ── Legacy handle() stub (never called by SOAR but kept for local testing) ─

    def handle(self, in_string: str) -> dict:
        """Not called by SOAR — kept for local standalone test server only."""
        return {"status": 200, "headers": {"Content-Type": "application/json"},
                "payload": json.dumps(dict(self))}

    def handleStream(self, handle, in_string):
        return None

    def done(self):
        pass


# ── Standalone test server ─────────────────────────────────────────────────────

def run_standalone_server(host: str = "localhost", port: int = 8743) -> None:
    """Local test server that mimics SOAR's handler invocation pattern."""
    import http.server

    class _MockRequest:
        def __init__(self, method, body, meta):
            self.method = method
            self.body = body
            self.META = meta

        def build_absolute_uri(self, path="/"):
            return f"http://localhost:{port}{path}"

    class _H(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _handle(self, method, body=b""):
            meta = {f"HTTP_{k.upper().replace('-','_')}": v
                    for k, v in self.headers.items()}
            meta["SERVER_NAME"] = host
            req = _MockRequest(method, body, meta)
            path = self.path.split("/")[-1] or "test"
            handler = SoarMcpRestHandler(req, [path])
            body_out = json.dumps(dict(handler)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body_out)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body_out)

        def do_GET(self):    self._handle("GET")
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            self._handle("POST", self.rfile.read(n))
        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers",
                             "ph-auth-token, Content-Type")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.end_headers()

    server = http.server.HTTPServer((host, port), _H)
    print(f"[SOAR MCP] Standalone server at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[SOAR MCP] Stopped.")


if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8743)
    args = parser.parse_args()
    run_standalone_server(host=args.host, port=args.port)
