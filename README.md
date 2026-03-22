# SOAR MCP Server

**Splunk SOAR On-Premises App — v1.1.0**

Exposes Splunk SOAR as an MCP (Model Context Protocol) server endpoint.
Claude Desktop, Claude Code, or any MCP-compatible AI client connects
directly to SOAR and gets structured access to cases, artifacts, playbooks,
and notes — without any external service or cloud dependency.

---

## Architecture

```
Claude Desktop / Claude Code / any MCP client
        │
        │  MCP (JSON-RPC 2.0 over HTTP)
        ▼
https://<soar>/rest/handler/phantom_soar_mcp_server/mcp
        │
        │  SOAR REST API (internal, ph-auth-token)
        ▼
  Splunk SOAR  ──  Cases, Artifacts, Playbooks, Notes, Users
```

Everything stays inside your network. No calls to Anthropic or any cloud service.

---

## Installation

1. Download `soar_mcp_server_v1.1.0.tar`
2. In SOAR: **Administration → Apps → Install App** → upload the TAR file
3. Configure the asset (optional — only needed for Test Connectivity):
   - **base_url**: e.g. `https://soar.example.com`
   - **auth_token**: from **Administration → User Management → Users → your user → Authorization Tokens**
4. Run **Test Connectivity** to verify the MCP endpoint is active

The MCP endpoint is live immediately after installation at:
```
https://<your-soar>/rest/handler/phantom_soar_mcp_server/mcp
```

---

## Connecting Claude

Run the **Get MCP Config** action in SOAR — the widget generates the exact
JSON snippets you need and lets you copy them with a single click.

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "splunk-soar": {
      "url": "https://soar.example.com/rest/handler/phantom_soar_mcp_server/mcp",
      "headers": {
        "ph-auth-token": "YOUR_SOAR_AUTH_TOKEN"
      }
    }
  }
}
```

Restart Claude Desktop after saving. SOAR will appear as a connected server
in the bottom-left corner.

### Claude Code (CLI)

```bash
claude mcp add splunk-soar \
  --transport http \
  --url "https://soar.example.com/rest/handler/phantom_soar_mcp_server/mcp" \
  --header "ph-auth-token: YOUR_SOAR_AUTH_TOKEN"
```

Or add to `~/.claude.json` manually:

```json
{
  "mcpServers": {
    "splunk-soar": {
      "type": "http",
      "url": "https://soar.example.com/rest/handler/phantom_soar_mcp_server/mcp",
      "headers": {
        "ph-auth-token": "YOUR_SOAR_AUTH_TOKEN"
      }
    }
  }
}
```

---

## Available Tools

### Read-Only (enabled by default)

| Tool | Description |
|---|---|
| `list_cases` | List cases with filters (status, severity, label, date range) |
| `get_case` | Full case detail including all artifacts and metadata |
| `search_cases` | Full-text search across case names and descriptions |
| `list_artifacts` | Artifacts for a case with optional type filter |
| `get_artifact` | Full artifact detail including CEF fields |
| `list_case_notes` | All analyst notes for a case |
| `list_playbooks` | Available playbooks with category filter |
| `get_playbook_run` | Status and result of a specific playbook execution |
| `list_action_runs` | Action run history for a case |
| `list_users` | SOAR users and roles |
| `get_soar_info` | SOAR version, hostname, and system information |

### Write (disabled by default — enable in `local/mcp.conf`)

| Tool | Description |
|---|---|
| `add_case_note` | Add a note to a case |
| `run_playbook` | Trigger a playbook on a case |
| `update_case_status` | Change case status (open, closed, etc.) |
| `update_case_severity` | Change case severity |
| `update_case_owner` | Reassign case owner |
| `create_artifact` | Add an artifact to a case |

---

## Configuration

The app reads configuration from `mcp.conf`. Bundled defaults live in
`default/mcp.conf` inside the app. To override settings without editing app
files, create `local/mcp.conf` (survives app upgrades).

SOAR app directory (typically):
```
/opt/phantom/apps/phantom_soar_mcp_server_<version>/
├── default/mcp.conf   ← bundled defaults (do not edit)
└── local/mcp.conf     ← your overrides (create this file)
```

### Enabling Write Tools

Create `/opt/phantom/apps/phantom_soar_mcp_server_<version>/local/mcp.conf`:

```ini
[tools]
enable_add_case_note = true
enable_run_playbook = true
enable_update_case_status = false
enable_update_case_severity = false
enable_update_case_owner = false
enable_create_artifact = false
```

### Safety Settings

```ini
[safety]
advisory_disclaimer = AI-generated content. Verify before acting.
allowed_labels =
max_items_per_case = 200
min_severity = low
```

### Full Reference

```ini
[server]
timeout = 30
max_results = 50
ssl_verify = true
log_tool_calls = true
protocol_version = 2024-11-05
server_name = Splunk SOAR MCP Server
server_version = 1.1.0

[tools]
enable_list_cases = true
enable_get_case = true
enable_search_cases = true
enable_list_artifacts = true
enable_get_artifact = true
enable_list_case_notes = true
enable_list_playbooks = true
enable_get_playbook_run = true
enable_list_action_runs = true
enable_list_users = true
enable_get_soar_info = true
enable_add_case_note = false
enable_run_playbook = false
enable_update_case_status = false
enable_update_case_severity = false
enable_update_case_owner = false
enable_create_artifact = false

[safety]
advisory_disclaimer = AI-generated content. Verify before acting.
allowed_labels =
max_items_per_case = 200
min_severity = low
```

---

## Security Notes

- Use a dedicated read-only SOAR user for Claude connections.
- Write tools are disabled by default and must be explicitly enabled.
- All tool calls are logged by SOAR's built-in audit trail when
  `log_tool_calls = true` (default).
- SSL verification is enabled by default. Set `ssl_verify = false` only
  for self-signed certs in isolated test environments.

---

## Standalone Testing (without SOAR)

```bash
cd /opt/phantom/apps/phantom_soar_mcp_server_<version>/
python3 soar_mcp_handler.py --host 127.0.0.1 --port 8743
```

Then point any MCP test client at `http://127.0.0.1:8743`.

---

## License

Copyright 2026 Andreas Buis. All rights reserved.
