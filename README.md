# SOAR MCP Server

**Splunk SOAR On-Premises App** · runs on **Python 3.13** · [latest release](https://github.com/abuis78/soar_mcp_server/releases/latest)

Transform Splunk SOAR into an MCP (Model Context Protocol) server endpoint for direct AI integration. Claude Desktop, Claude Code, Claude.ai, or any MCP-compatible AI client can connect directly to your SOAR instance for structured access to cases, artifacts, playbooks, and analyst notes — completely on-premises, with zero external dependencies.

**Key Features:**
- ✅ **100% On-Premises** — No cloud services, no data exfiltration
- ✅ **Read-Only by Default** — 30 read tools active, 10 write tools opt-in via UI checkboxes (40 tools total)
- ✅ **Asset-Based Configuration** — Control all tool availability via SOAR UI checkboxes, no SSH required
- ✅ **COA Visual Editor Stack** — Full playbook graph inspection, validation, diff, and import/export (v1.6.3+)
- ✅ **AI Instructions Field** — Inject SOC-specific context into every AI session
- ✅ **Scoped MCP Tokens** — Per-user, revocable, optionally tool-restricted tokens (v1.5.0+)
- ✅ **Audit Trail** — All tool calls logged via SOAR's native audit system

---

## ⚠️ Disclaimer — Use at Your Own Risk

> **This is an independently developed community app. It is NOT an official Splunk product and is provided "as-is", without warranty of any kind, express or implied.**
>
> By installing or using this software, **you accept full and sole responsibility** for all consequences of its operation, including but not limited to:
>
> - **Live data modification** — Write tools add notes, change case status/severity/owner, and create artifacts directly on your SOAR instance. Changes are immediate and may not be reversible.
> - **Playbook execution** — `run_playbook` triggers real automated response actions: firewall rule changes, email quarantine, endpoint isolation, IP blocking, account disabling, and other potentially irreversible operations that affect live systems outside of SOAR.
> - **Playbook import** — `import_playbook` can overwrite existing playbooks. There is no built-in undo.
> - **Test harness** — `create_container` and `enable_test_harness` instantiate test infrastructure on your SOAR host. These are intended exclusively for development and testing. **Never enable on a production SOAR instance.**
> - **AI-driven decisions** — The AI operates within the permissions of the configured SOAR user account and can execute any action that account is authorized to perform. AI models may interpret ambiguous instructions in unexpected ways and act accordingly.
> - **Data exposure** — Case content, artifact values (IPs, hashes, domains), analyst notes, and playbook structures are transmitted to the AI model. When using cloud-based AI clients (Claude.ai), this data leaves your network.
>
> **Anthropic and Splunk bear no responsibility for any outcomes resulting from use of this app.**
>
> Always apply the **principle of least privilege**: run with a dedicated read-only SOAR service account and enable write tools only after validating behavior in a non-production environment. You are the operator — all consequences of AI-initiated actions are yours.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Claude Desktop / Claude Code / Claude.ai / MCP Clients     │
└────────────────────────┬────────────────────────────────────┘
                         │
                         │  MCP Protocol (JSON-RPC 2.0 over HTTP/SSE)
                         │  Authentication: ph-auth-token header
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  https://<your-soar>/rest/handler/soarmcpserver_<appid>/<asset> │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  SOAR MCP Server App (Python REST Handler)           │  │
│  │  ├─ Tool Registry (asset config checkboxes)          │  │
│  │  ├─ AI Instructions Context Injection                │  │
│  │  ├─ Scoped Token Auth (v1.5.0+)                      │  │
│  │  └─ Request Validation & Logging                     │  │
│  └───────────────────────────────────────────────────────┘  │
│                         │                                    │
│                         │  SOAR REST API (internal)          │
│                         │  Authentication: ph-auth-token     │
│                         ▼                                    │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Splunk SOAR Core                                     │  │
│  │  ├─ Cases (Containers)                                │  │
│  │  ├─ Artifacts (CEF IOCs)                              │  │
│  │  ├─ Playbooks & COA Visual Editor                     │  │
│  │  ├─ Notes & Analyst Comments                          │  │
│  │  └─ User & System Info                                │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Everything stays inside your network.** No calls to Anthropic or any cloud service. The AI client connects directly to your SOAR instance via authenticated HTTPS.

---

## Installation

> **Compatibility:** Developed and verified on **Splunk SOAR On-Prem 8.5.0.248**.
> The COA Visual Editor tools target SOAR 8.5+. The app runs as a generic
> Python 3 app and is verified **Python 3.13-ready** (CI-gated).

### Step 1: Install the App

1. **Download** the latest `soar_mcp_server_vX.Y.Z.tar` from the [Releases page](https://github.com/abuis78/soar_mcp_server/releases/latest)
2. In SOAR: **Apps → Install App** (top-right button)
3. **Upload** the TAR file
4. Click **Install** and wait for completion

The app installs immediately and the MCP endpoint becomes active at:
```
https://<your-soar>/rest/handler/soarmcpserver_ff5f68f3-353c-4d89-9767-967ef5d99117/<asset_name>
```

Use the endpoint shown by **Test Connectivity** or **Get MCP Config**. The last
path segment is the SOAR asset name, for example `mcp`.

### Step 2: Configure the Asset

1. Navigate to **Apps → SOAR MCP Server → Asset Settings**
2. Click **Configure New Asset** (or edit the existing asset)

**Required Configuration:**

| Field | Value | Purpose |
|-------|-------|---------|
| **Asset Name** | `soar_mcp_server` | Identifies this MCP server instance |
| **Base URL** | `https://soar.example.com` | Your SOAR instance URL (for Test Connectivity) |
| **Auth Token** | `ph-auth-token-xxx` | From **Administration → User Management → Users → [user] → Authorization Tokens** |

**Optional Configuration:**

| Field | Default | Description |
|-------|---------|-------------|
| **AI Instructions** | _(empty)_ | Additional context sent to the AI on every MCP session. Describe your SOAR environment, naming conventions, severity triage rules, escalation procedures. |
| **enable_test_harness** | `false` | Enable the built-in playbook self-test harness (`create_container` tool). Same effect as `enable_test_harness = true` in `mcp.conf [safety]` — no SSH required. **Never enable on production.** |
| **ssl_verify** | `true` | Verify TLS certificates for SOAR API calls. Disable only for lab/test instances with self-signed certificates — never on production. |
| **scoped_tokens_enabled** | `false` | Enable per-user, revocable scoped MCP tokens (v1.5.0+). |
| **scoped_tokens_required** | `false` | Reject requests that do not present a valid scoped token. |

**Tool Selection (Checkboxes):**

All tools are individually enabled/disabled via checkboxes. See [Available Tools](#available-tools) for the full list.

### Step 3: Test Connectivity

1. Click **Test Connectivity** in the asset configuration
2. Verify output shows:
   - ✅ MCP endpoint is reachable
   - ✅ Auth token is valid
   - ✅ Tool configuration applied successfully
   - ✅ Number of enabled tools
   - ✅ Security posture summary (write tools, ssl_verify, token mode)

**The MCP server is now ready for Claude connections.**

> **⚠️ Run Test Connectivity after every (re)install.** The REST handler resolves
> the SOAR base URL from `phantom.rest` and, as a trusted fallback, from the
> **Base URL** you configure here (persisted to `local/asset_overrides.json`).
> On SOAR builds where `phantom.rest` is not importable from the app runtime
> (observed on 8.5.0.248), the app depends entirely on that configured Base URL.
> A fresh install resets `local/`, so you must set **Base URL** and run **Test
> Connectivity** once per install — otherwise tools fail fast with
> *"Could not determine the SOAR base URL"* (by design, never an insecure
> header-derived fallback).

---

## Connecting Claude

**Easiest Method:** Run the **Get MCP Config** action in SOAR — the custom widget generates ready-to-copy JSON snippets for Claude Desktop and Claude Code with your exact endpoint URL and auth token already filled in.

### Option 1: Claude Desktop (macOS/Windows)

**Config File Location:**
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "splunk-soar": {
      "url": "https://soar.example.com/rest/handler/soarmcpserver_ff5f68f3-353c-4d89-9767-967ef5d99117/mcp",
      "headers": {
        "ph-auth-token": "YOUR_SOAR_AUTH_TOKEN"
      }
    }
  }
}
```

Save and restart Claude Desktop. Verify: look for "splunk-soar" in the bottom-left MCP server list.

### Option 2: Claude Code (CLI)

```bash
claude mcp add splunk-soar \
  --transport http \
  --url "https://soar.example.com/rest/handler/soarmcpserver_ff5f68f3-353c-4d89-9767-967ef5d99117/mcp" \
  --header "ph-auth-token: YOUR_SOAR_AUTH_TOKEN"
```

**Verify:**
```bash
claude mcp list
# Should show: splunk-soar (connected)
```

### Option 3: Claude.ai (Web Interface)

**Prerequisites:** Enterprise Claude.ai subscription with MCP connector support; SOAR accessible from the internet or via VPN/proxy.

1. Claude.ai → **Settings → Integrations → MCP Servers → + Add Server**
2. **URL**: `https://soar.example.com/rest/handler/soarmcpserver_ff5f68f3-353c-4d89-9767-967ef5d99117/mcp`
3. **Auth Type**: Custom Header — `ph-auth-token: YOUR_SOAR_AUTH_TOKEN`

> ⚠️ When using Claude.ai, SOAR case data (titles, descriptions, artifact values, analyst notes) transits Anthropic's cloud infrastructure. Review [Anthropic's data retention policy](https://www.anthropic.com/legal/privacy) before connecting a production SOAR instance.

### Troubleshooting Connection Issues

| Issue | Solution |
|-------|----------|
| "Connection refused" | `curl -I https://soar.example.com/rest/handler/soarmcpserver_ff5f68f3-353c-4d89-9767-967ef5d99117/mcp` |
| "Unauthorized" | Check auth token in SOAR UI → User Management |
| "SSL certificate verify failed" | Add SOAR's SSL cert to system trust store, or disable **SSL Verify** in the SOAR asset config for test instances only |
| Tools not appearing | Run **Test Connectivity** to refresh tool registry; reconnect the MCP client (tool schemas are cached at connect time) |
| "Tool disabled" error | Enable tool checkbox in asset config → Test Connectivity |
| "Could not determine the SOAR base URL" | Set **Base URL** in the asset config and run **Test Connectivity** (required once per install — see the note in Step 3) |

---

## Available Tools

All tools are controlled via **asset configuration checkboxes** in the SOAR UI. Changes take effect immediately after **Test Connectivity**.

### Case & Investigation Tools (Read — Default: Enabled)

| Tool | Parameters | Returns |
|------|-----------|---------|
| **`list_cases`** | `status`, `severity`, `label`, `owner`, `limit` | Cases with ID, title, status, severity, owner, tags |
| **`get_case`** | `case_id` | Full case detail: description, artifact/note counts, playbook runs, custom fields |
| **`search_cases`** | `query`, `limit` | Cases matching keyword search across title + description |
| **`list_artifacts`** | `case_id`, `artifact_type` | Artifacts with CEF fields (IP/domain/hash/URL/email) |
| **`get_artifact`** | `artifact_id` | Full artifact detail: all CEF fields, tags, source, associated case |
| **`list_case_notes`** | `case_id` | Notes with content, author, timestamp |
| **`list_playbooks`** | `active_only`, `category` | Playbooks with name, description, category, active status |
| **`get_playbook_run`** | `run_id` | Run status (running/success/failed), start/end time, action results |
| **`list_action_runs`** | `case_id`, `limit` | Action runs: action name, app, status, results, timestamp |
| **`list_users`** | `role` | Users: username, display name, email, role |
| **`get_soar_info`** | _(none)_ | SOAR version, build number, license status, app count |

### App & Asset Inspection Tools (Read — Default: Enabled)

| Tool | Parameters | Returns |
|------|-----------|---------|
| **`list_apps`** | `name_filter` | Installed SOAR apps/connectors with name, version, vendor |
| **`list_assets`** | `app_filter` | Configured SOAR assets with app, name, configured status |
| **`get_action_schema`** | `app_name`, `action_name` | Input parameters and output fields for a specific action |

### COA Visual Editor Tools (Read — Default: Enabled)

These tools provide deep inspection of playbook structure via the COA graph. On SOAR 8.5+, the graph is automatically retrieved from the export archive when the live COA endpoint returns no data.

| Tool | Parameters | Returns |
|------|-----------|---------|
| **`get_playbook_coa_summary`** | `playbook_id` | Compact node/edge summary of the COA graph |
| **`list_playbook_nodes`** | `playbook_id` | Structured listing of all COA nodes (type, name, action, app) |
| **`list_playbook_edges`** | `playbook_id` | Structured listing of all COA edges (source → target, conditions) |
| **`resolve_playbook_current_id`** | `playbook_id` | Resolves any playbook ID (draft/published/revision) to current active ID |
| **`get_playbook_identity_map`** | `playbook_id` | All revision IDs for a playbook (useful for diffing versions) |
| **`export_playbook`** | `playbook_id` | Export playbook as base64-encoded gzip TAR archive |
| **`diff_playbook_versions`** | `playbook_id_a`, `playbook_id_b` | Semantic diff between two playbook versions |
| **`verify_layout_only_change`** | `playbook_id_a`, `playbook_id_b` | Strict pass/fail: confirms a change is layout-only (x/y positions, no logic) |
| **`check_saved_generated_python_drift`** | `playbook_id` | Detects drift between saved Python and what SOAR would generate from the COA graph |
| **`check_datapath_selectability`** | `playbook_id`, `node_id`, `field` | Schema-based check whether a datapath field is selectable in the VPE |
| **`validate_playbook_bundle`** | `playbook_id` | Multi-check validation: structure, Python compile/lint, COA integrity, SOAR compat |
| **`check_visual_editor_compat`** | `playbook_id` | Aggregated compatibility check for the COA Visual Editor |

### Diagnostics & Capability Tools (Read — Default: Enabled)

| Tool | Parameters | Returns |
|------|-----------|---------|
| **`diagnose_soar_mcp_environment`** | `output_format` | App version, endpoint shape, handler reachability, `/rest/version` probe, security posture + findings. Reports only token *presence*, never the value. |
| **`detect_soar_capabilities`** | `playbook_id`, `output_format` | How this SOAR instance behaves: COA graph availability, export fallback, Python payload source, validation method |
| **`audit_visual_playbook`** | `playbook_id`, `output_format` | One-call pre-edit audit: stale/current, counts, warnings/errors, trigger/type, Python source, validation + drift, recommendations. Verdict pass/warn/fail/**unknown** |
| **`generate_mcp_client_config`** | _(none)_ | Copy-ready MCP client config snippets (Claude Desktop/Code, Cursor, CLI). Token is always a placeholder — never the real auth token |

### Write Tools (Default: Disabled) ⚠️

Write tools modify live SOAR data. Enable only after reviewing the [Disclaimer](#️-disclaimer--use-at-your-own-risk) and testing in a non-production environment.

| Tool | Action | Risk |
|------|--------|------|
| **`add_case_note`** | Adds analyst note/comment to a case | 🟡 Low — audit trail preserved |
| **`create_artifact`** | Adds new IOC/observable to a case | 🟡 Low — can pollute case data |
| **`update_case_owner`** | Reassigns case to a different analyst | 🟠 Medium — disrupts workflow |
| **`update_case_severity`** | Changes severity (high/medium/low/informational) | 🟠 Medium — affects SLA/priority |
| **`update_case_status`** | Changes status (open/closed/resolved/new/in_progress) | 🔴 High — can close active investigations |
| **`run_playbook`** | Triggers automated playbook execution on a case | 🔴 High — executes real response actions |
| **`import_playbook`** | Imports a playbook from a base64-encoded TAR archive | 🔴 High — can overwrite existing playbooks |
| **`save_playbook_layout_only`** | Saves node x/y positions to the VPE (layout only, no logic) | 🟡 Low — `dry_run=true` by default. **Preview-only:** hidden from `tools/list` until the COA write endpoint is verified |

### Test Harness (Disabled by Default — Never Use on Production) 🚫

| Tool | Action | Requirement |
|------|--------|-------------|
| **`create_container`** | Creates an isolated test container for playbook self-testing | `enable_test_harness` + SOAR user with **container-create** rights |
| **`delete_container`** | Deletes a suite-owned test container (cleanup) | `enable_test_harness` + SOAR user with **container-delete** rights |

Enable via asset config: check **`enable_test_harness`** → Save → Test Connectivity. No SSH or file edit required (v1.6.9+).

**Required SOAR permissions for the full create → test → cleanup loop:** the token
user needs create/update rights on containers, artifacts, and notes **and**
container-**delete** rights for cleanup. A user with only *Automation /
Automation Engineer* can typically create and mutate test containers but **cannot
delete** them (delete returns HTTP 403) — grant a role with container-delete, or
clean up test cases manually. `delete_container` reports a 403 as a clear cleanup
finding, not a silent success.

**Container label portability:** `test` is not a valid container label on every
SOAR install. Set the label your instance actually allows (e.g. `events`) via
`[safety] test_container_label` in `mcp.conf`; `create_container` uses it as the
default. `delete_container` treats a container as suite-owned (safe to delete) if
its label matches `test_container_label` **or** its name starts with
`[safety] test_container_name_prefix` (default `mcp_`).

---

## Configuration

### Asset-Based Configuration (Recommended)

All configuration is managed from **SOAR UI → Apps → SOAR MCP Server → Asset Settings**. Changes take effect after **Test Connectivity** — no app restart, no SSH, no file edits.

**Configuration Fields:**

| Field | Type | Purpose |
|-------|------|---------|
| **Base URL** | String | SOAR instance URL. Used for Test Connectivity **and** as the trusted base-URL fallback when `phantom.rest` is unavailable (required once per install — see Step 3) |
| **Auth Token** | Password | SOAR authorization token |
| **SSL Verify** | Boolean | Verify TLS certs for handler API callbacks; disable only for test/self-signed instances |
| **AI Instructions** | Text | Context injected into every MCP session |
| **enable_test_harness** | Boolean | Enables test harness / `create_container` + `delete_container` (v1.6.9+) |
| **scoped_tokens_enabled** | Boolean | Enable per-user scoped tokens (v1.5.0+) |
| **scoped_tokens_required** | Boolean | Reject requests without a valid scoped token |
| **tool_*** | Boolean × 40 | Enable/disable each tool individually |

**`mcp.conf`-only settings** (`local/mcp.conf`, applied on Test Connectivity):

| Key (section) | Purpose |
|---|---|
| `[server] base_url` / `soar_base_url` | Static trusted SOAR base URL — a persistent alternative to the asset **Base URL** (survives reinstalls); credentials in the URL are rejected |
| `[safety] require_confirmation` | Two-step commit for **all** write tools (confirm_token + preview → execute); persistent, single-use, TTL |
| `[safety] test_container_label` | Default/allowed test-container label (default `test`; set to a label your instance has, e.g. `events`) |
| `[safety] test_container_name_prefix` | Name prefix that marks a container as suite-owned/safe-to-delete (default `mcp_`) |

**Override Precedence (highest → lowest):**
```
Asset config checkboxes (local/asset_overrides.json)
  └─ local/mcp.conf
       └─ default/mcp.conf (bundled defaults — do not edit)
```

### File-Based Configuration (Advanced)

For operators who prefer file-based overrides or need to set options not exposed in the UI.

**File Location:**
```
/opt/phantom/apps/phantom_soar_mcp_server_<version>/
├── default/mcp.conf   ← Bundled defaults (do not edit)
└── local/mcp.conf     ← Your overrides (create this file)
```

**Example: Safety Settings**
```ini
[safety]
# Prepend disclaimer to all AI-generated content
advisory_disclaimer = true

# Restrict write tools to specific case labels
allowed_labels = phishing,malware

# Max artifacts returned per case
max_items_per_case = 100

# Minimum case severity for write operations
min_severity = medium

# Enable test harness (prefer asset config checkbox instead)
enable_test_harness = false
```

**Applying File Changes:** Run **Test Connectivity** after editing. No restart required.

---

## Security & Best Practices

### Authentication

**Use a dedicated, minimal-permission SOAR user:**
1. Create a service account: `mcp_claude_readonly`
2. Assign **Analyst (Read-Only)** role or a custom role with the minimum required permissions
3. Generate an auth token for this user only
4. **Never use admin tokens for MCP connections**

**Token Management:**
- Rotate tokens every 90 days
- Store in a secure credential manager (1Password, Bitwarden, etc.)
- Never commit tokens to version control
- Monitor token usage via SOAR audit logs

### Write Tool Safety

Enable write tools in graduated phases:

| Phase | Enabled Tools | Risk |
|-------|--------------|------|
| **1 — Read-Only** | All read tools | 🟢 Minimal |
| **2 — Annotation** | + `add_case_note` | 🟡 Low |
| **3 — Enrichment** | + `create_artifact` | 🟡 Low |
| **4 — Triage** | + `update_case_owner`, `update_case_severity` | 🟠 Medium |
| **5 — Orchestration** | + `run_playbook`, `update_case_status`, `import_playbook` | 🔴 High |

**Human-in-the-Loop pattern:**
```
Claude: "I recommend running 'Enrich IP' on case 12345. Proceed?"
Analyst: [Reviews and confirms]
Claude: [Calls run_playbook]
SOAR:   [Executes, logs with analyst approval reference]
```

### Data Privacy

**What Claude sees:**
- Case metadata (title, description, status, severity, owner, tags)
- Artifact data (IOC values, CEF fields)
- Analyst notes
- Playbook structure (COA graph, node actions, edges)

**What Claude does NOT see:**
- SOAR passwords or auth tokens
- Credential vault secrets
- System configuration outside of what tools explicitly return

**Data Residency:**
- **Claude Desktop/Code**: all data processed locally
- **Claude.ai Web**: MCP requests transit Anthropic cloud — see [Anthropic's privacy policy](https://www.anthropic.com/legal/privacy)

### Incident Response

**If an MCP token is compromised:**
1. Revoke immediately: **User Management → [user] → Authorization Tokens → Delete**
2. Review audit logs for unauthorized activity
3. Issue a new token and update Claude configs

**If unauthorized write operations are detected:**
1. Disable write tools via asset config → uncheck all write tools → Test Connectivity
2. Review `phantom.log` for source IP, timestamp, affected cases
3. Investigate the AI prompt chain that triggered the action

---

## Use Cases

### AI-Assisted Investigation (Read-Only)
```
"Show me all open phishing cases from the last 24 hours with high severity"
→ list_cases → 23 results

"Get details on case 12345 and list all artifacts"
→ get_case + list_artifacts → full IOC picture

"Cross-reference this domain across all cases"
→ search_cases → finds 8 related cases
```

### Playbook Inspection & Validation (COA Tools)
```
"Show me the COA graph for playbook 'Phishing Response'"
→ get_playbook_coa_summary + list_playbook_nodes + list_playbook_edges

"Has the Python in playbook 42 drifted from the COA graph?"
→ check_saved_generated_python_drift → detects mismatches

"Diff this playbook against the previous version"
→ diff_playbook_versions → semantic change summary

"Is this change really layout-only or did logic change?"
→ verify_layout_only_change → strict pass/fail
```

### Playbook Import (Advanced)
```
"Import this updated playbook bundle to SOAR"
→ import_playbook → resolves SCM, uploads TAR, returns new playbook ID
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| "Missing app directory" on install | TAR lacks top-level directory entry | Rebuild from parent dir: `cd /parent && tar -czf app.tar soar_mcp_server/` |
| "Connection refused" | MCP endpoint not accessible | `curl -I https://soar.example.com/rest/handler/soarmcpserver_ff5f68f3-353c-4d89-9767-967ef5d99117/mcp` |
| "Unauthorized" | Invalid auth token | Regenerate token in SOAR UI |
| node_count = 0 | COA endpoint empty on SOAR 8.5 | Fixed in v1.6.5 — export archive fallback is automatic |
| Python compile skipped | No `code`-type nodes | Fixed in v1.6.6 — Python extracted from export archive automatically |
| import_playbook HTTP 400/403 | Wrong body format or read-only SCM | Fixed in v1.6.8 — uses JSON body with `scm_id` (int), skips "community" SCM |
| Tools not appearing in Claude | Asset config not applied | Run **Test Connectivity** |
| "Tool disabled" error | Checkbox unchecked | Enable in asset config → Test Connectivity |

**Debug Logging:**
```ini
# local/mcp.conf
[logging]
level = DEBUG
log_payloads = true  # ⚠️ Exposes sensitive data
```
```bash
tail -f /var/log/phantom/soar/phantom.log | grep soar_mcp_handler
```

---

## Changelog

### v1.11.6 (2026-07-11)
- 🐛 **#104 Python 3.13** — manifest `python_version` `"3"` → `"3.13"`; SOAR install-log analysis proved `"3"` was treated as Python 3.9. The app now installs and runs on Python 3.13 (code was already 3.13-clean, CI-gated).

### v1.11.4–v1.11.5 (2026-07-11)
- 🐛 **#116** — `require_confirmation` confirmed writes now execute: the confirmation store is file-backed (survives SOAR's multi-process handler); token hash only, single-use, TTL.
- 🐛 **#117** — portable test-harness cleanup: configurable `test_container_label` / `test_container_name_prefix`; `delete_container` recognises suite-owned containers by label **or** name prefix; delete-403 reported as an actionable cleanup finding.
- 🧹 App package no longer ships `test_*.py` / `scripts/` / `.github/` (enforced by the package linter).

### v1.11.0–v1.11.3 (2026-07-11)
- ✨ **#68 Capability detection** — `detect_soar_capabilities` + `soar_mcp_capabilities.py`; per-process cache; node/edge tools report *why* a graph is empty.
- ✨ **#69 `audit_visual_playbook`** — one-call pre-edit audit with pass/warn/fail/**unknown** verdict.
- 🐛 **#93 base_url** — trusted fallback (asset config + `mcp.conf [server] base_url`) when `phantom.rest` is unavailable; fixes `MissingSchema`; keeps #58's no-header-trust. Credentials in a base_url are rejected.

### v1.9.0–v1.10.0 (2026-07-10)
- ✨ **#74** structured response envelope; **#70** unified credential-safe error classifier.
- ✨ **#51** security-posture report in Test Connectivity; **#67** `diagnose_soar_mcp_environment` (read-only).
- 🐛 **#58/#85 base_url** fail-secure resolution (live-verified on 8.5.0.248).

### v1.8.0 (2026-07-10)
- ✨ **#71** package-hygiene linter; **#72** `generate_mcp_client_config`; **#66** gated `delete_container`; **#50** optional two-step write confirmation.

### v1.7.0–v1.7.2 (2026-07-10) — Security hardening
- 🔒 Credential handling: no auth token on unverified TLS (#39), on disk (#40), in action data (#53), or in the widget (#52); `/tmp` debug writers removed (#55).
- 🔒 Stored-XSS strip in `create_artifact` (#42); `_filter` input sanitized (#49); scoped-token/legacy rate-limiting (#44); Fernet key can live out-of-band (#56); mint token not persisted (#54).
- 🔒 Write tools **off by default**; `cryptography` declared in `pip3_dependencies` (#43).
- ✨ SOAR 8.5 COA compatibility series (#34–#38): client-side playbook filters, graph normalization, unified Python selection, `isError` flag, `ssl_verify` asset checkbox.

### v1.6.9 (2026-07-10)
- ✨ **`enable_test_harness` as asset config checkbox** — toggle the test harness from the SOAR UI without SSH access. Asset checkbox takes precedence over `mcp.conf [safety]`; falls back to `mcp.conf` when not set.

### v1.6.8 (2026-07-10)
- 🐛 **#32 `import_playbook` — final fix**: JSON body with `scm_id` (integer), not `scm` (string); skips read-only and "community" SCMs in auto-resolution. HTTP 403 response body now surfaced in error message instead of swallowed.

### v1.6.7 (2026-07-10)
- 🐛 **#32 intermediate attempt**: switched to multipart upload — reverted in v1.6.8 after SOAR rejected with "Must provide valid json in post request"

### v1.6.6 (2026-07-10)
- 🐛 **#31 `validate_playbook_bundle` python_compile always skipped**: action/decision/utility playbooks have no `code`-type nodes. Fixed by extracting the `.py` file directly from the export archive.

### v1.6.5 (2026-07-10)
- 🐛 **#30 `node_count = 0` on SOAR 8.5**: `/coa/playbooks/{id}` returns an empty `coa_data` for all playbooks on SOAR 8.5 — the graph is only available in the export archive. Added `_get_graph_from_export()` fallback; all 6 COA graph call sites now use it automatically.

### v1.6.4 (2026-07-10)
- 🐛 **#30 first-pass fix**: added multi-shape COA data detection (`coa_data["coa"]["data"]["nodes"]` and `coa_data["data"]["nodes"]`); added `_coa_shape_debug()` diagnostic helper

### v1.6.3 (2026-07-09)
- ✨ **COA Visual Editor tool stack** — 18 new tools for playbook graph inspection, validation, diffing, and import/export:
  `list_apps`, `list_assets`, `get_action_schema`, `export_playbook`, `import_playbook`, `create_container`, `resolve_playbook_current_id`, `get_playbook_identity_map`, `get_playbook_coa_summary`, `list_playbook_nodes`, `list_playbook_edges`, `check_saved_generated_python_drift`, `check_datapath_selectability`, `diff_playbook_versions`, `verify_layout_only_change`, `validate_playbook_bundle`, `check_visual_editor_compat`, `save_playbook_layout_only`
- ✨ `post_multipart()` helper on `SoarApiClient` for future binary upload endpoints

### v1.5.0 (2026-06-01)
- ✨ **Scoped MCP tokens** — per-user, revocable, optionally tool-restricted. New actions: `mint mcp token`, `list mcp tokens`, `revoke mcp token`
- ✨ Per-call audit logging on `soar_mcp.audit` logger; never logs the token
- ✨ Per-token rate limiting (default 120 req/min, sliding window)
- ✨ Cursor support in Config Builder widget (`${env:SOAR_MCP_TOKEN}`)
- 🔒 SOAR call token encrypted at rest with Fernet; token store `chmod 600`, atomic writes, constant-time comparison

### v1.6.2 (2026-04-20)
- ✨ Asset-based configuration with UI checkboxes
- ✨ AI Instructions field for SOC-specific context injection
- ✨ Custom Config Builder widget with copy-paste snippets
- 🐛 Fixed SSL verification for self-signed certificates
- 🐛 Fixed pagination for large case lists

### v1.3.0 (2026-03-20)
- ✨ Initial public release: 11 read tools, 6 write tools, file-based `mcp.conf`, standalone mock mode

---

## Contributing

**Bug Reports:** [GitHub Issues](https://github.com/abuis78/soar_mcp_server/issues) — include SOAR version, app version, error message, `phantom.log` excerpt.

**Feature Requests:** GitHub Issues with `[FEATURE]` tag.

**Pull Requests:** Fork → branch → commit → PR. Include tests for new tools; update `LIVE_TOOLS.md`.

---

## Credits

**Author:** Andreas Buis ([@abuis78](https://github.com/abuis78))  
**Organization:** originvibe  
**Created With:** Claude (Anthropic)

---

## License

Copyright 2026 Andreas Buis. All rights reserved.

Free for Splunk SOAR customers. May not be redistributed or resold. No warranty provided — use at your own risk. Source code provided for transparency and customization.

**Splunk and SOAR are trademarks of Splunk Inc. This app is not affiliated with or endorsed by Splunk Inc.**

---

## Support

- **Community:** [GitHub Issues](https://github.com/abuis78/soar_mcp_server/issues) · [GitHub Discussions](https://github.com/abuis78/soar_mcp_server/discussions)
- **Enterprise:** support@originvibe.de — include SOAR version, app version, logs
- **Splunk Platform:** contact Splunk Support directly — this app is community-developed, not Splunk-supported

---

**⭐ If you find this useful, please star the repo!**
