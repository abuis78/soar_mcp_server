"""
SOAR MCP Server — MCP REST Handler

This module implements the Splunk SOAR persistent REST endpoint that exposes
the Model Context Protocol (MCP) server interface.

The handler is registered in soar_mcp_server.json as:
    "rest_handler": "soar_mcp_handler.SoarMcpRestHandler"

It is accessible at:
    https://<soar-host>/rest/handler/phantom_soar_mcp_server/mcp

Protocol implemented: MCP JSON-RPC 2.0 (Streamable HTTP transport)
  POST /mcp  — JSON-RPC request/response
  GET  /mcp  — SSE stream (session events, for future use)

Authentication:
  The MCP client must pass the SOAR auth token in the request header:
    ph-auth-token: <your-soar-auth-token>
  This token is used for all subsequent SOAR REST API calls.

MCP client configuration (Claude Desktop):
  {
    "mcpServers": {
      "splunk-soar": {
        "url": "https://<soar-host>/rest/handler/phantom_soar_mcp_server/mcp",
        "headers": { "ph-auth-token": "<token>" }
      }
    }
  }

MCP client configuration (Claude Code / ~/.claude.json):
  {
    "mcpServers": {
      "splunk-soar": {
        "type": "http",
        "url": "https://<soar-host>/rest/handler/phantom_soar_mcp_server/mcp",
        "headers": { "ph-auth-token": "<token>" }
      }
    }
  }

Copyright 2026 Andreas Buis
"""

from __future__ import annotations

import json
import logging
import os
import sys

# ── Ensure app directory is on sys.path for local imports ─────────────────────
_app_dir = os.path.dirname(os.path.abspath(__file__))
if _app_dir not in sys.path:
    sys.path.insert(0, _app_dir)

from soar_mcp_config import McpServerConfig, get_config
from soar_mcp_tools import TOOL_SCHEMAS, SoarApiClient, call_tool

logger = logging.getLogger(__name__)

# ── MCP JSON-RPC error codes ───────────────────────────────────────────────────
_JSONRPC_PARSE_ERROR = -32700
_JSONRPC_INVALID_REQUEST = -32600
_JSONRPC_METHOD_NOT_FOUND = -32601
_JSONRPC_INVALID_PARAMS = -32602
_JSONRPC_INTERNAL_ERROR = -32603

# ── Splunk SOAR persistent REST handler base class ────────────────────────────
try:
    from splunk.persistconn.application import PersistentServerConnectionApplication as _SoarBase

    _SOAR_RUNTIME = True
except ImportError:
    # Outside SOAR (local testing): use a simple stub
    _SOAR_RUNTIME = False

    class _SoarBase:  # type: ignore[no-redef]
        """Minimal stub for local testing outside SOAR."""

        def __init__(self, *args, **kwargs):
            pass


class SoarMcpRestHandler(_SoarBase):
    """
    Persistent REST handler implementing the MCP server protocol for SOAR.

    Registered via the 'rest_handler' field in soar_mcp_server.json.
    SOAR routes all requests to /rest/handler/phantom_soar_mcp_server/mcp
    to the handle() method of this class.

    The class is initialised once and kept alive across requests (persistent),
    which means config and client state are cached efficiently.
    """

    def __init__(self, command_line: str = "", command_arg: str = "") -> None:
        super().__init__()
        self._config: McpServerConfig = get_config()
        logger.info(
            "[SOAR MCP] REST handler initialised. Tools enabled: %d",
            len(self._config.enabled_tools),
        )

    # ── SOAR entry point ───────────────────────────────────────────────────────

    def handle(self, in_string: str) -> dict:
        """
        Main SOAR request handler.  Called for every HTTP request routed to this handler.

        Args:
            in_string: Raw JSON string representing the full SOAR request envelope.

        Returns:
            Dict with 'status', 'headers', and 'payload' keys.
        """
        # Reload config on every request so that any tool checkbox changes
        # made via the asset config (and written by the connector) are
        # picked up without restarting the handler process.
        self._config = get_config(reload=True)

        try:
            request = json.loads(in_string)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.error("[SOAR MCP] Failed to parse SOAR request envelope: %s", exc)
            return self._soar_response(400, self._error_response(None, _JSONRPC_PARSE_ERROR, "Malformed request"))

        method = self._extract_http_method(request)
        headers = self._extract_headers(request)
        body_bytes = self._extract_body(request)

        # Extract auth token from request headers
        auth_token = self._extract_auth_token(headers)

        # Extract SOAR base URL from the request context
        soar_base_url = self._extract_base_url(request)

        if method == "GET":
            return self._handle_get(headers, auth_token, soar_base_url)
        elif method == "POST":
            return self._handle_post(body_bytes, headers, auth_token, soar_base_url)
        else:
            return self._soar_response(405, {"error": f"Method {method} not allowed"})

    def handleStream(self, handle, in_string: str):
        """Not implemented — MCP does not use Splunk's streaming interface."""
        return None

    def done(self) -> None:
        pass

    # ── HTTP method handlers ───────────────────────────────────────────────────

    def _handle_get(self, headers: dict, auth_token: str, soar_base_url: str) -> dict:
        """
        Handle GET /mcp — SSE endpoint for MCP Streamable HTTP transport.

        Returns a minimal SSE response with the endpoint event.
        Full SSE streaming is limited in SOAR's persistent REST framework;
        this provides compatibility for MCP clients that check for SSE support.
        """
        sse_body = (
            "event: endpoint\n"
            "data: {}\n\n"
        )
        return {
            "status": 200,
            "headers": {
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Access-Control-Allow-Origin": "*",
            },
            "payload": sse_body,
        }

    def _handle_post(
        self, body: bytes, headers: dict, auth_token: str, soar_base_url: str
    ) -> dict:
        """
        Handle POST /mcp — MCP JSON-RPC 2.0 request processing.

        Parses the JSON-RPC request, dispatches to the appropriate handler,
        and returns the JSON-RPC response.
        """
        # ── Parse JSON-RPC ─────────────────────────────────────────────────────
        try:
            rpc = json.loads(body) if body else {}
        except (json.JSONDecodeError, TypeError):
            return self._soar_response(
                200, self._error_response(None, _JSONRPC_PARSE_ERROR, "Invalid JSON in request body")
            )

        if not isinstance(rpc, dict):
            return self._soar_response(
                200, self._error_response(None, _JSONRPC_INVALID_REQUEST, "Request must be a JSON object")
            )

        rpc_id = rpc.get("id")
        method = rpc.get("method", "")
        params = rpc.get("params") or {}

        logger.info("[SOAR MCP] JSON-RPC method: %s (id=%s)", method, rpc_id)

        # ── Validate auth ──────────────────────────────────────────────────────
        if not auth_token:
            return self._soar_response(
                401,
                self._error_response(
                    rpc_id,
                    -32000,
                    "Missing authentication. Add 'ph-auth-token' to your MCP client headers.",
                ),
            )

        # Build API client
        client = SoarApiClient(soar_base_url, auth_token, self._config)

        # ── Dispatch JSON-RPC method ───────────────────────────────────────────
        try:
            if method == "initialize":
                result = self._handle_initialize(params)
            elif method == "notifications/initialized":
                # Notification — no response needed per MCP spec
                return self._soar_response(204, "")
            elif method == "tools/list":
                result = self._handle_tools_list(params)
            elif method == "tools/call":
                result = self._handle_tools_call(params, client)
            elif method == "ping":
                result = {}
            else:
                return self._soar_response(
                    200,
                    self._error_response(rpc_id, _JSONRPC_METHOD_NOT_FOUND, f"Method not found: {method}"),
                )
        except Exception as exc:
            logger.exception("[SOAR MCP] Unhandled error in method '%s': %s", method, exc)
            return self._soar_response(
                200,
                self._error_response(rpc_id, _JSONRPC_INTERNAL_ERROR, "Internal server error"),
            )

        return self._soar_response(200, self._success_response(rpc_id, result))

    # ── MCP method implementations ─────────────────────────────────────────────

    def _handle_initialize(self, params: dict) -> dict:
        """
        Handle MCP initialize request.

        Returns server capabilities, protocol version, and instructions for the AI.
        The instructions include built-in SOAR context plus any custom text set
        by the administrator in the asset configuration (ai_instructions field).
        """
        client_info = params.get("clientInfo") or {}
        client_version = params.get("protocolVersion", "unknown")
        logger.info(
            "[SOAR MCP] Initialize from client: %s v%s (protocol %s)",
            client_info.get("name", "unknown"),
            client_info.get("version", "?"),
            client_version,
        )

        # Built-in instructions — always sent to every AI client.
        # This tells the LLM what SOAR is and how to use these tools effectively.
        # The LLM does NOT need to know the endpoint URL — it receives tool schemas
        # automatically via tools/list and knows what to call and how.
        base_instructions = (
            "You are connected to a Splunk SOAR (Security Orchestration, Automation & Response) "
            "instance via the Model Context Protocol. "
            "SOAR is a security platform that manages incidents (called 'cases' or 'containers'), "
            "IOC observables (called 'artifacts'), analyst notes, and automated response playbooks.\n\n"
            "How to work effectively:\n"
            "- Start with list_cases or search_cases to find relevant incidents.\n"
            "- Use get_case to read all details of a case (status, severity, owner, description).\n"
            "- Use list_artifacts to see IOCs attached to a case (IPs, domains, hashes, emails, URLs).\n"
            "- Use list_case_notes to read the investigation history and analyst findings.\n"
            "- Use list_playbooks to discover available automated response options.\n"
            "- Severity levels: high > medium > low > informational.\n"
            "- Case statuses: new, open, in_progress, resolved, closed.\n\n"
            "Write tools (add_case_note, run_playbook, update_case_status, etc.) modify live SOAR "
            "data. Always describe what you plan to do and wait for analyst confirmation before "
            "executing any write operation. Never run a playbook without explicit approval."
        )

        # Append custom instructions set by the admin in the asset configuration.
        # Use this to describe your specific SOAR environment, naming conventions,
        # escalation rules, on-call contacts, or any SOC-specific context.
        custom = (self._config.ai_instructions or "").strip()
        if custom:
            instructions = base_instructions + "\n\n--- Environment-specific context ---\n" + custom
        else:
            instructions = base_instructions

        return {
            "protocolVersion": self._config.protocol_version,
            "capabilities": {
                "tools": {"listChanged": False},
            },
            "serverInfo": {
                "name": self._config.server_name,
                "version": self._config.server_version,
            },
            "instructions": instructions,
        }

    def _handle_tools_list(self, params: dict) -> dict:
        """
        Handle MCP tools/list request.

        Returns only tools that are enabled in the current mcp.conf.
        """
        tools = []
        for tool_name, schema in TOOL_SCHEMAS.items():
            if tool_name not in self._config.enabled_tools:
                continue
            tools.append({
                "name": tool_name,
                "description": schema["description"],
                "inputSchema": schema["inputSchema"],
            })

        logger.info("[SOAR MCP] tools/list returning %d tools", len(tools))
        return {"tools": tools}

    def _handle_tools_call(self, params: dict, client: SoarApiClient) -> dict:
        """
        Handle MCP tools/call request.

        Validates the tool is enabled, dispatches to the tool implementation,
        and wraps the result in MCP content format.
        """
        tool_name = params.get("name", "")
        arguments = params.get("arguments") or {}

        if not tool_name:
            raise ValueError("tools/call requires 'name' parameter")

        if tool_name not in self._config.enabled_tools:
            if tool_name in TOOL_SCHEMAS:
                result_text = (
                    f"Tool '{tool_name}' is installed but currently disabled. "
                    f"To enable it: open the SOAR MCP Server asset configuration, "
                    f"check the '{tool_name}' checkbox, save, and run 'Test Connectivity' "
                    f"to apply the change."
                )
            else:
                result_text = f"Unknown tool: '{tool_name}'. Call tools/list to see available tools."

            return {
                "content": [{"type": "text", "text": result_text}],
                "isError": True,
            }

        # Execute tool
        result_text = call_tool(tool_name, arguments, client, self._config)

        return {
            "content": [{"type": "text", "text": result_text}],
            "isError": False,
        }

    # ── Response builders ──────────────────────────────────────────────────────

    @staticmethod
    def _success_response(rpc_id, result: dict) -> dict:
        return {"jsonrpc": "2.0", "id": rpc_id, "result": result}

    @staticmethod
    def _error_response(rpc_id, code: int, message: str) -> dict:
        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "error": {"code": code, "message": message},
        }

    @staticmethod
    def _soar_response(status: int, payload) -> dict:
        """Build a SOAR-formatted HTTP response dict."""
        if isinstance(payload, (dict, list)):
            content_type = "application/json"
        elif isinstance(payload, str) and payload.startswith("event:"):
            content_type = "text/event-stream"
        else:
            content_type = "application/json"

        return {
            "status": status,
            "headers": {
                "Content-Type": content_type,
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Headers": "ph-auth-token, Content-Type, Authorization",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            },
            "payload": payload,
        }

    # ── Request parsing helpers ────────────────────────────────────────────────

    @staticmethod
    def _extract_http_method(request: dict) -> str:
        return str(request.get("method", request.get("request_method", "POST"))).upper()

    @staticmethod
    def _extract_headers(request: dict) -> dict:
        """Normalize request headers to a lowercase-key dict."""
        raw = request.get("headers") or {}
        if isinstance(raw, dict):
            return {k.lower(): v for k, v in raw.items()}
        if isinstance(raw, list):
            return {str(item[0]).lower(): str(item[1]) for item in raw if len(item) >= 2}
        return {}

    @staticmethod
    def _extract_body(request: dict) -> bytes:
        """Extract the request body as bytes."""
        body = request.get("body") or request.get("payload") or request.get("data") or b""
        if isinstance(body, str):
            return body.encode("utf-8")
        if isinstance(body, (bytes, bytearray)):
            return bytes(body)
        return b""

    @staticmethod
    def _extract_auth_token(headers: dict) -> str:
        """Extract the SOAR auth token from headers (ph-auth-token or Authorization: Bearer)."""
        # Prefer ph-auth-token (native SOAR header)
        token = headers.get("ph-auth-token", "").strip()
        if token:
            return token
        # Fallback: Authorization: Bearer <token>
        auth_header = headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            return auth_header[7:].strip()
        return ""

    @staticmethod
    def _extract_base_url(request: dict) -> str:
        """
        Determine the SOAR base URL from the incoming request context.

        SOAR injects connection information into the request envelope.
        We derive the base URL so the MCP tools can call back to the SOAR REST API.
        """
        connection = request.get("connection") or {}
        server = request.get("server") or {}

        # Try to get host from headers
        raw_headers = request.get("headers") or {}
        headers: dict
        if isinstance(raw_headers, dict):
            headers = {k.lower(): v for k, v in raw_headers.items()}
        elif isinstance(raw_headers, list):
            headers = {str(item[0]).lower(): str(item[1]) for item in raw_headers if len(item) >= 2}
        else:
            headers = {}

        host = headers.get("host", "")

        # Parse host:port
        if host and ":" in host:
            hostname, port = host.rsplit(":", 1)
        elif host:
            hostname, port = host, "443"
        else:
            hostname = (
                connection.get("server_name")
                or server.get("server_name")
                or "localhost"
            )
            port = str(
                connection.get("server_port")
                or server.get("server_port")
                or "8443"
            )

        # Use HTTPS by default (SOAR is always HTTPS in production)
        return f"https://{hostname}:{port}"


# ==============================================================================
# Standalone HTTP server (for local testing without SOAR)
# ==============================================================================

def run_standalone_server(host: str = "localhost", port: int = 8743) -> None:
    """
    Run the MCP handler as a standalone HTTP server for local testing.

    This mode does NOT require SOAR. It uses Python's built-in http.server.
    The server expects requests in the same format the handler uses internally.

    Usage:
        python3 soar_mcp_handler.py --host localhost --port 8743

    Then configure Claude Code:
        {
          "mcpServers": {
            "splunk-soar-test": {
              "type": "http",
              "url": "http://localhost:8743/mcp",
              "headers": { "ph-auth-token": "YOUR_SOAR_TOKEN" }
            }
          }
        }
    """
    import http.server
    import urllib.parse

    handler_instance = SoarMcpRestHandler()

    class _RequestHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            logger.info("HTTP: " + fmt, *args)

        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "ph-auth-token, Content-Type, Authorization")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.end_headers()

        def _build_soar_envelope(self, method: str, body: bytes) -> str:
            headers_list = [[k, v] for k, v in self.headers.items()]
            envelope = {
                "method": method,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": body.decode("utf-8", errors="replace"),
                "connection": {
                    "server_name": self.server.server_address[0],
                    "server_port": self.server.server_address[1],
                },
            }
            return json.dumps(envelope)

        def _send_response(self, soar_resp: dict):
            status = soar_resp.get("status", 200)
            payload = soar_resp.get("payload", {})
            headers = soar_resp.get("headers", {})
            if isinstance(payload, (dict, list)):
                body = json.dumps(payload).encode("utf-8")
            elif isinstance(payload, str):
                body = payload.encode("utf-8")
            else:
                body = b""
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            envelope = self._build_soar_envelope("GET", b"")
            resp = handler_instance.handle(envelope)
            self._send_response(resp)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            envelope = self._build_soar_envelope("POST", body)
            resp = handler_instance.handle(envelope)
            self._send_response(resp)

    print(f"[SOAR MCP Server] Standalone test server running at http://{host}:{port}/mcp")
    print(f"[SOAR MCP Server] Configure Claude Code with:")
    print(f'  {{"mcpServers": {{"splunk-soar": {{"type": "http", "url": "http://{host}:{port}/mcp", "headers": {{"ph-auth-token": "YOUR_TOKEN"}}}}}}}}')
    print(f"[SOAR MCP Server] Press Ctrl+C to stop.")

    server = http.server.HTTPServer((host, port), _RequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[SOAR MCP Server] Stopped.")


# ── CLI entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    parser = argparse.ArgumentParser(description="SOAR MCP Server — standalone test mode")
    parser.add_argument("--host", default="localhost", help="Bind host (default: localhost)")
    parser.add_argument("--port", type=int, default=8743, help="Bind port (default: 8743)")
    args = parser.parse_args()

    run_standalone_server(host=args.host, port=args.port)
