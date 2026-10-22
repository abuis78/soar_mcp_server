# SOAR MCP Server

**Splunk SOAR On-Premises App** · runs on **Python 3.13** · [latest release](https://github.com/abuis78/soar_mcp_server/releases/latest)

Transform Splunk SOAR into an MCP (Model Context Protocol) server endpoint for direct AI integration. Claude Desktop, Claude Code, Claude.ai, or any MCP-compatible AI client can connect directly to your SOAR instance for structured access to cases, artifacts, playbooks, and analyst notes — completely on-premises, with zero external dependencies.

**Key Features:**
- ✅ **100% On-Premises** — No cloud services, no data exfiltration
- ✅ **Read-Only by Default** — 33 read tools active, 12 write tools + 1 approval tool opt-in via UI checkboxes (46 tools total)
- ✅ **Asset-Based Configuration** — Control all tool availability via SOAR UI checkboxes, no SSH required
- ✅ **COA Visual Editor Stack** — Full playbook graph inspection, validation, diff, and import/export (v1.6.3+)
- ✅ **AI Instructions Field** — Inject SOC-specific context into every AI session
- ✅ **Scoped MCP Tokens** — Per-user, revocable, optionally tool-restricted tokens (v1.5.0+)
- ✅ **Audit Trail** — All tool calls logged via SOAR's native audit system

---

## Overview

**In one sentence:** this app turns your Splunk SOAR instance into an MCP server endpoint, so an AI client can talk to SOAR directly through structured, analyst-focused tools.

### How it works
- Runs as a **REST handler** inside SOAR at `https://<your-soar>/rest/handler/soarmcpserver_<appid>/<asset>`
- Speaks the **MCP protocol** (JSON-RPC 2.0 over HTTP/SSE), authenticated with a `ph-auth-token` header
- The handler calls SOAR's internal **REST API** and translates it into analyst-friendly MCP tools
- **Fully on-premises** — the app itself adds no cloud dependency and performs no external data transfer

### The tool model
- **46 tools total:** 33 read-only (enabled by default) + 12 write tools + `approve_action` (v1.17.0+, opt-in per SOAR UI checkbox)
- **Read:** inspect cases, artifacts, playbooks, and notes; inspect, validate, and diff the COA playbook graph
- **Write (deliberately opt-in):** add notes, change case status/severity/owner, create artifacts, `run_playbook` (triggers real response actions), and `import_playbook`
- Tool availability and all configuration are controlled entirely through **asset-config checkboxes** — no SSH required
- **Scoped tokens** (per-user, revocable, optionally tool-restricted) plus an **audit trail** via SOAR's native logging

### Core value and the risk it carries
The app is the **bridge between an AI analyst and your SOAR automation**. Read-only is the safe default; once write tools are enabled, the AI can **act live** within the permissions of the configured SOAR user — playbooks may change firewall rules, quarantine mail, isolate endpoints, and more. Always apply **least privilege**: run with a dedicated read-only service account and enable write tools only after validating behaviour in a non-production environment. For `run_playbook` specifically, see the [Policy Layer](#policy-layer--gated-autonomous-run_playbook), which can gate execution behind explicit approval rules.

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

> **Compatibility:** Requires **Splunk SOAR On-Prem 8.5+** (`min_phantom_version`
> = `8.5.0`) — the app runs on **Python 3.13**, which is an 8.5 platform feature.
> Verified on 8.5.0.248 (product/platform version confirmed via the SOAR logs).

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
| **agent_read_exceptions** | _(empty)_ | v1.15.0+ — comma-separated read-only tools an **agent** token may still call directly (SPEC-MCP MCP-L02). Empty = none. Every entry must be deliberately justified; it is flagged in the security posture. |
| **policy_mode** | _(empty)_ | v1.16.0+ — decision path for the 12 write tools (SPEC-MCP MCP-G03). **Empty = today's behaviour** (in-app policy layer gates `run_playbook` only, see `policy_enabled`). `service` = **every** write tool is decided by the external Policy Manager before it runs, fail-closed. Anything else (incl. the reserved `embedded`) = invalid → all write tools blocked. Read tools are never affected. |
| **policy_service_url** | _(empty)_ | v1.16.0+ — base URL of the Policy Manager (`https://host:port`, no `/v1`). Required for `policy_mode = service`; `https` only. |
| **policy_timeout_s** | `5` | v1.16.0+ — request timeout for Policy Manager calls (0.5–120 s). A timeout **refuses** the write (no fallback). |
| **policy_client_cert** | _(empty)_ | v1.16.0+ — mTLS client certificate: file **path** on the SOAR host (PEM). Never the content. |
| **policy_client_key** | _(empty)_ | v1.16.0+ — mTLS client key: file path on the SOAR host (PEM). Never logged. |
| **policy_ca** | _(empty)_ | v1.16.0+ — CA bundle (file path) used to verify the Policy Manager certificate. Empty = system trust store. |
| **tool_approve_action** | `false` | v1.17.0+ — enable the approval tool `approve_action(freigabe_id)` (policy_mode = `service`). Human analysts with a scoped MCP token approve held actions; agent and broker tokens never see it. |

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

### Upgrades & Persistence (important)

SOAR **replaces the entire app directory on every install/upgrade**, so anything
under `local/` is **not** preserved:

| State | Survives upgrade? | Persistent alternative |
|-------|:---:|---|
| **Asset config** (Base URL, Auth Token, tool checkboxes, `enable_test_harness`, …) | ✅ yes — stored in SOAR's DB | — (this is the persistent store) |
| `local/mcp.conf` (incl. `[server] base_url`) | ❌ removed on upgrade | Put **Base URL** in the **asset config** instead |
| `local/asset_overrides.json` | ❌ removed on upgrade | Re-created by **Test Connectivity** |
| `local/mcp_tokens.json` (scoped MCP tokens) | ❌ removed on upgrade | **Re-mint** tokens after upgrade |

**After every upgrade:**
1. Run **Test Connectivity** (re-syncs the asset config → `local/`, restores `base_url`).
2. If you use scoped MCP tokens, **re-mint** them (`mint mcp token`).

For a persistent `base_url` that does not depend on re-running Test Connectivity,
set the **asset config Base URL** (survives upgrades) rather than `mcp.conf`
`[server] base_url` (app-directory-local). `diagnose_soar_mcp_environment`
reports a clear `base_url_unresolved` finding when this configuration is missing.

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
| **`run_playbook`** | Triggers automated playbook execution on a case (by ID **or** name; can be governed by the [Policy Layer](#policy-layer--gated-autonomous-run_playbook)) | 🔴 High — executes real response actions |
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
| **agent_read_exceptions** | Text | Read-only tools an agent token may call directly (v1.15.0+, default none) |
| **policy_mode** | Text | `""` = today's path / `service` = Policy Manager decides every write tool (v1.16.0+) |
| **policy_service_url** | Text | Policy Manager base URL, `https` only (v1.16.0+) |
| **policy_timeout_s** | Numeric | Policy Manager timeout in seconds, default 5 (v1.16.0+) |
| **policy_client_cert** / **policy_client_key** / **policy_ca** | Text | mTLS material as file paths on the SOAR host (v1.16.0+) |
| **tool_*** | Boolean × 45 | Enable/disable each tool individually |
| **tool_approve_action** | Boolean | Approval tool for held actions in `policy_mode = service` (v1.17.0+, default off) |

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

## Policy Layer — Gated-Autonomous `run_playbook`

> Since **v1.12.0**. Opt-in, default **off**. 📖 **Full details:
> [docs/policy-layer.md](docs/policy-layer.md).**

An **unbypassable SOC guard** in the single execution chokepoint (`call_tool`) that
governs every `run_playbook`. Instead of "the AI can run playbooks", you get
**graded autonomy** — each run is evaluated to one of four gates **before** it can
execute:

| Gate | Effect |
|------|--------|
| `ALLOW` | Runs autonomously (still audited) |
| `APPROVE_1CLICK` | Held for **one** human approval |
| `APPROVE_2PERSON` | Held for **two different** human approvals (no self-approval) |
| `DENY` | Blocked |

**How the gate is chosen:** `final = max(base, risk, target_override)` — the playbook
**category** sets the base gate (data-driven in [`policy/policy_config.json`](policy/policy_config.json)),
risk can only **escalate** (never relax), and critical asset/identity targets force
2-person. **Fail-safe:** an unknown category, a config/load error, or a missing
approver identity **holds or denies — never auto-runs**.

**Approvals** reuse scoped MCP tokens for the approver identity (`soar_user_id`);
the token store is file-backed, `fcntl`-locked, single-use, and TTL-bound.

**Enable it (recommended):** Asset config → check **`policy_enabled`** and
**`tool_run_playbook`** → Save → Test Connectivity → **reconnect your MCP client once**.
Advanced: `[policy] enabled = true` in `local/mcp.conf`.

**Quick test:** point `run_playbook` at a `Containment`-category playbook → expect
`⏸ Approval required by policy — 2 distinct approver(s)` instead of a run. Set the
category to `Enrichment` → it runs (`ALLOW`). Every decision is logged as
`[soar_mcp.policy]` in `phantom.log`. See
[docs/policy-layer.md](docs/policy-layer.md) for the decision algorithm, risk
formula, approval flow, config reference, fail-safe guarantees, and the full test
procedure.

### Policy Manager mode (v1.16.0+, SPEC-MCP Phase 2)

The asset field **`policy_mode`** selects who decides the **12 write tools**
(`run_playbook`, `add_case_note`, `create_artifact`, `create_container`, `delete_container`,
`import_playbook`, `save_playbook_layout_only`, `update_case_owner`, `update_case_severity`,
`update_case_status`, `create_custom_function_draft`, `update_custom_function_draft`):

| `policy_mode` | Who decides | Behaviour |
|---------------|-------------|-----------|
| _(empty, default)_ | in-app policy layer (above) | **Exactly today's behaviour** — only `run_playbook` is gated, and only when `policy_enabled` is on. |
| `service` | external **Policy Manager** (`POST /v1/decide`) | Every write tool is decided before it runs: `ALLOW` → runs, `DENY` → blocked, `APPROVE_*` → held. **Fail-closed:** Policy Manager unreachable, timeout, TLS error or malformed answer → the write is refused, no fallback to the in-app layer. |
| anything else (incl. reserved `embedded`) | nobody | Invalid configuration — every write tool is refused until corrected; the security posture flags `policy_mode_invalid`. |

Read tools are never affected by `policy_mode`. Settings: `policy_service_url` (`https` only),
`policy_timeout_s`, optional mTLS as file paths (`policy_client_cert`, `policy_client_key`,
`policy_ca`); the same keys exist under `[policy]` in `mcp.conf`.

What the Policy Manager receives per write: the action (`tool` → `aktion.art`, target IDs,
parameters, playbook category for `run_playbook`), the caller (`principal_type`, `token_id`,
`soar_user_id`, `agent_id`; the legacy `ph-auth-token` path counts as `mensch`), asset values
collected from the case (same enrichment as the in-app layer) and the optional
**`agent_context`** object every write tool now accepts (`lauf_id`, `stufe` 0–4, `domaene`,
`tipping_off`, `beleg_ids`, `urteil` with `empfehlung` / `gegenargumente` / `unsicherheiten` /
`konfidenz`). For **agent** tokens `agent_context` is mandatory in `service` mode: missing
evidence is refused locally as `NO_EVIDENCE`, an incomplete judgement as `INCOMPLETE_JUDGEMENT`
(no Policy Manager round-trip). Humans may omit it. **Dry-runs** (`dry_run=true` on
`save_playbook_layout_only` and the custom-function draft tools) write nothing and skip the
Policy Manager (audit only).

**Approvals and emergency stop (v1.17.0+, SPEC-MCP Phase 3):** a decision that needs approval
(`APPROVE_1CLICK` / `APPROVE_2PERSON`) is held: the ⏸ message carries `entscheidung_id`,
`freigabe_id` and `ablauf`, and the app remembers the held action under its `freigabe_id`
(`local/held_actions.json`, mode 0600, expires with `ablauf`). Two ways to redeem it, both via
the Policy Manager's `approve` / `consume` (which also enforce "the requester never approves"
and "two different users"):

1. **`approve_action(freigabe_id)`** (canonical; enable `tool_approve_action`) — human analysts
   with a scoped MCP token only; the token identity is the approver. The call that completes the
   approval redeems it (`consume`) and **executes the held action**, returning its result. Agent
   and broker tokens neither see nor can call it; the legacy `ph-auth-token` has no identity and is
   refused.
2. **Re-call the tool** with the same arguments plus `freigabe_id` once all approvals are in —
   the compatibility path for agents and clients without a UI. Pending approvals are reported
   as `erteilt/noetig`; a changed tool or arguments is refused (`ACTION_CHANGED`).

Approval in `service` mode is exactly one `consume` (single use); unreachable Policy Manager,
`gueltig = false`, rejected/expired/consumed approvals never execute. In the default mode the
in-app approval flow is unchanged and `freigabe_id` is merely an alias of `approval_token`.

**Emergency stop (Not-Aus):** before an **agent** token's write is decided or redeemed the app asks
`GET /v1/halt`; halted or unknown state refuses with `HALTED`. Humans, brokers and the legacy token
keep working (the Policy Manager still checks the halt on its side).

The wire format (request `aktion` / `kontext` incl. `principal_type`, `initiator`, `artefakt_werte`;
`HaltStatus {angehalten, grund}`, `ConsumeResult {gueltig, code}`, `ApprovalStatus {status, erteilt,
noetig, code}`) follows `policy_client.base` from the PolicyManager repo (branch `feature/p1-core`,
P1.5). Still assumed until the PolicyManager P3 service exists: the request bodies of
`approve` / `reject` (`{"freigebender": <id>}`) and `consume` (the decide request).

`diagnose_soar_mcp_environment` reports `policy_manager` (`mode`, `reachable`, `halted`) and
`held_actions` (count), flags `policy_manager_unreachable` / `policy_manager_halted` and hints
`policy_service_without_scoped_tokens` (no identity → no approvals; set `scoped_tokens_required`).
Every decision, approval and redemption is logged as `[soar_mcp.policy] service …` with
`entscheidung_id` / `freigabe_id` in `phantom.log`; approval tokens and mTLS key material are
never logged.

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

**Principal type (v1.15.0+, SPEC-MCP):** every scoped token minted with `mint mcp token` carries a
`principal_type` — `mensch` (human analyst, default), `agent` (AI agent, needs `agent_id`) or
`broker` (Tool Broker adapter). Tokens minted before v1.15.0 count as `mensch`. An **agent** token
gets **no direct read tools**: `tools/list` hides them and any call is refused with
`USE_TOOL_BROKER` — agents read SOAR data only through Tool Broker templates. Exceptions are an
explicit admin decision (`agent_read_exceptions`) and are marked in the audit log. Humans and the
legacy full `ph-auth-token` path are unchanged.

**Broker tokens (v1.18.0+, SPEC-MCP Phase 4, MCP-L03..L05):** a `broker` token is the Tool
Broker's adapter identity and **reads only**. At mint, `allowed_tools` is required and cut to
`READ_ONLY_TOOLS` (write and approval tools are reported as "not granted"); `tools/list` shows a
broker only read tools and any write/approval call is refused (`denied:broker_write`), whatever the
allow-list says. Every broker call must carry the Tool Broker's **`broker_aufruf_id`** as a top-level
argument (1–128 chars, letters/digits/`._:-`; refused as `denied:missing_broker_aufruf_id` otherwise);
`agent_id` and `lauf_id` are optional and land in the audit line. A broker's `limit` is capped at
`max_results` before the tool runs. Catalog tools without a `limit` parameter (`list_apps`,
`list_assets`, `get_action_schema`, `export_playbook`, …) stay unbounded. Broker tokens minted
before v1.18.0 without an allow-list keep full read access; `diagnose_soar_mcp_environment`
flags them (`broker_tokens_without_allow_list`) — re-mint and revoke.

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

### v1.18.0 (2026-10-19) — SPEC-MCP Phase 4: broker tokens as Tool Broker adapter
Implements Phase 4 of the `soar_mcp_server` rebuild specification (epic [#165](https://github.com/abuis78/soar_mcp_server/issues/165)); decision OQ-3 (2026-10-19): the Tool Broker reads SOAR through this server as an adapter. **No change for human, agent or legacy tokens.**
- 🔒 **Broker allow-list (MCP-L03)** — `mint mcp token` with `principal_type = broker` requires `allowed_tools`; entries outside `READ_ONLY_TOOLS` are dropped and reported (`dropped_tools`); an empty result refuses the mint.
- 🚫 **Brokers never write (MCP-L05, AC-07, OQ-14)** — write and approval tools are hidden from a broker's `tools/list` and refused on call (`denied:broker_write`), even when the allow-list names them. One predicate drives both.
- 🧾 **Broker context (MCP-L04)** — `broker_aufruf_id` is mandatory for broker calls (`denied:missing_broker_aufruf_id`), `agent_id` / `lauf_id` optional; all three are documented on the 33 read-tool schemas and audited (a broker's `agent_id` comes from the argument). `limit` is capped at `max_results` before the tool runs; catalog tools without `limit` stay unbounded (documented).
- 🩺 **Diagnostics** — `broker_tokens_without_allow_list` warns about pre-4.1 broker tokens (count only).
- 🧪 15 new tests (442 total).

### v1.17.0 (2026-10-19) — SPEC-MCP Phase 3: approvals, approve_action, emergency stop
Implements Phase 3 of the `soar_mcp_server` rebuild specification (epic [#165](https://github.com/abuis78/soar_mcp_server/issues/165)). **No behaviour change in the default `policy_mode`** (AC-11); everything below applies to `policy_mode = service`.
- 🔌 **Wire format aligned with `policy_client.base` (MCP-G02, concept OQ-15)** — request `kontext.principal_type` / `initiator` / `agent_id` / `artefakt_werte`, `ziel` as a list; `HaltStatus {angehalten, grund}`, `ConsumeResult {gueltig, code}`, `ApprovalStatus {status, erteilt, noetig, code}`; new client methods `approve` / `reject`; `consume` carries the decide request (`ACTION_CHANGED` guard). Source: PolicyManager repo `feature/p1-core` @ `c6851e7` (P1.5).
- 🗂️ **Held actions (MCP-W06, OQ-16)** — `policy/held_actions.py`: a held write is remembered under its `freigabe_id` (`local/held_actions.json`, 0600, fcntl, expires with `ablauf`, never stores tokens).
- 🔁 **Redeem by re-call (MCP-W06, OQ-11, AC-05)** — every write tool accepts `freigabe_id`; approved → `consume` → execute, pending → ⏸ `erteilt/noetig`, anything else refused. Default mode: `freigabe_id` is an alias of `approval_token`.
- ✅ **New tool `approve_action(freigabe_id)` (MCP-W06, OQ-7)** — 46 tools total: new category "gate tool" (neither read nor write), asset checkbox `tool_approve_action` (off by default). Humans with a scoped MCP token only; hidden from and refused for `agent` / `broker` tokens (audit `denied:human_only`). The completing approval consumes and executes the held action. Execution bypasses `require_confirmation` (the approval is the stronger confirmation) and runs with the SOAR token of the last approver, as today.
- 🛑 **Emergency stop (MCP-W08, AC-09, PM-F31)** — agent writes and redemptions ask `GET /v1/halt` first; halted or unknown → `HALTED` without a decide round-trip. Humans, brokers and the legacy token are unaffected.
- 🩺 **Diagnostics (MCP-G06)** — `held_actions` count; info finding `policy_service_without_scoped_tokens` (OQ-7).
- 📐 **Remaining assumptions** (code comments `ASSUMPTION`): request bodies of `approve` / `reject` (`{"freigebender": …}`) and `consume` (decide request). No live verification against a real Policy Manager was possible; all HTTP paths are covered by a local fake server, all flows by `StubPolicyClient`.
- ⏳ **Not in this release:** swap of `policy/client.py` for the `policy_client` wheel (once PM-P3 ships `ServicePolicyClient`), broker tool-list hiding (OQ-14, Phase 4).
- 🧪 57 new tests (426 total).

### v1.16.0 (2026-10-19) — SPEC-MCP Phase 2: Policy Manager service mode
Implements Phase 2 of the `soar_mcp_server` rebuild specification (epic [#165](https://github.com/abuis78/soar_mcp_server/issues/165)). **No behaviour change unless `policy_mode` is set**: the default (empty) keeps today's path exactly (AC-11); read tools are never gated.
- ⚙️ **`policy_mode` transition rule (MCP-G03, concept OQ-8)** — new asset fields `policy_mode`, `policy_service_url`, `policy_timeout_s`, `policy_client_cert`, `policy_client_key`, `policy_ca` (also `mcp.conf [policy]`). `""` = in-app layer as before, `service` = external Policy Manager, anything else (incl. reserved `embedded`) = invalid → every write tool refused; posture flag `policy_mode_invalid`.
- 🔌 **Policy Manager client (MCP-G02/G04, AN-01/02/04)** — `policy/client.py`: `https`-only HTTP client with optional mTLS (paths only), timeout, strict response parsing (`entscheidung_id`, `gate`, `freigaben_noetig`, `freigabe_id`, `ablauf`, `code`), `PolicyClientError` kinds `config|tls|timeout|unreachable|http|contract`; `StubPolicyClient` for tests.
- 🛡️ **Policy adapter for every write tool (MCP-W01..W05/W07/W09)** — `policy/service_gate.py` decides all 12 write tools in `service` mode before execution: `ALLOW` runs, `DENY` blocks (`HALTED` / `NO_EVIDENCE` / `INCOMPLETE_JUDGEMENT`), `APPROVE_*` holds. **Fail-closed, no fallback.** Dry-runs skip the decision (OQ-13).
- 👤 **Caller identity in the gate (MCP-W04, OQ-7)** — `Principal` (type, `token_id`, `soar_user_id`, `agent_id`) travels from the handler into `call_tool` and the gates; legacy `ph-auth-token` = `mensch`. Never carries the token value.
- 🧾 **`agent_context` on all write tools (MCP-W07, OQ-12)** — optional object (`lauf_id`, `stufe`, `domaene`, `tipping_off`, `beleg_ids`, `urteil`); required for `agent` principals in `service` mode, validated locally before any network call. `lauf_id` inside `agent_context` is preferred for the audit line.
- 🩺 **Diagnostics (MCP-G06)** — `diagnose_soar_mcp_environment` reports `policy_manager` and flags `policy_manager_unreachable` / `policy_manager_halted`.
- ⏳ **Not in this release:** approval redemption (`approve_action` / consume), halt enforcement via a live Policy Manager, broker tool-list hiding (OQ-14) — Phase 3/4, after Policy Manager P3.
- 📐 **Marked assumptions** (code comments `ASSUMPTION`, to be reconciled with the Policy Manager P3 interface): DENY reason in top-level `code`; `GET /v1/halt` → `{"halted": bool}`; consume success = HTTP 200; `GET /health` 200 + JSON object = reachable; request fields `initiator`, `aktion.parameter`, `kontext.asset_werte`. No live verification against a real Policy Manager was possible yet; coverage is via a local fake HTTP server.
- 🧪 113 new tests (369 total).

### v1.15.0 (2026-10-18) — SPEC-MCP Phase 1: principal type + agent read gate
Implements Phase 1 of the `soar_mcp_server` rebuild specification (SPEC-MCP v0.1). **No behaviour change for existing tokens or the legacy `ph-auth-token` path**; the new gate applies only to tokens minted as `agent`.
- ✨ **Principal type on scoped tokens (MCP-G01)** — `mint mcp token` takes `principal_type` (`mensch` | `agent` | `broker`, default `mensch`) and `agent_id` (required for `agent`). Stored in the token store (format version unchanged), returned by mint/list; pre-existing entries read as `mensch`.
- 🔒 **Agent read gate (MCP-L01)** — an `agent` token gets no direct read tools: `tools/list` hides all 33 read-only tools and `tools/call` refuses them with `USE_TOOL_BROKER` (audit `denied:use_tool_broker`). One predicate drives both, so hidden == refused. Enabled write tools remain callable (they go through the policy adapter in Phase 2).
- ⚙️ **`agent_read_exceptions` (MCP-L02)** — asset-config field / `mcp.conf [policy]`: explicit, admin-justified read tools an agent may still call. Default empty; only read-only names are accepted; a call via exception is audited as `ok:agent_read_exception`; the security posture flags `agent_read_exceptions_set`.
- 📝 **Audit identity (MCP-G05)** — every `tool_call` line carries `principal`, `token_id`, `agent_id`, `lauf_id`, `broker_aufruf_id` (the last two from top-level arguments, logged only). New `tool_result` line **after** execution with `result=ok|error|policy_blocked|policy_hold` — the hook where `entscheidung_id`/`freigabe_id` land in Phase 2.
- 🩺 **Diagnostics (MCP-G06, part)** — `diagnose_soar_mcp_environment` reports `principal_counts` (active tokens per principal type; counts only).
- 🧪 46 new tests (249 total). Phases 2–4 (policy adapter for all write tools, `policy_mode`, Policy Manager service, broker tokens) follow in separate releases.

### v1.14.0 (2026-07-16)
- ✨ **#159 Custom Functions — draft write (slice S2)** — two new WRITE tools (45 tools total: 33 read / 12 write, both **off by default**): `create_custom_function_draft` and `update_custom_function_draft`. They only ever write **drafts** — publishing is explicitly refused. Built on the facts the S1 probe measured, not on assumptions:
  - **Repository allowlist** (`custom_function_write_scm_ids`, set in the **asset-config UI**): **empty by default = no write to any repository**. `scm_id` values are instance-specific — the probe found `local` = 2 while `community` (Splunk's own content) = 1, so no code default could be safe.
  - **`is_read_only`** → refuse. **`draft_mode=false`** (publish) → refuse. **`commit_message`** required with source (API constraint). **`expected_revision`** must match the current `commit_sha` → else `REVISION_CONFLICT`, **no force update**. `name`/`scm_id` are never sent on update (immutable per API).
  - **`dry_run=true` by default** — previews the payload (source shown as length + sha256, never echoed) and writes nothing. The #50 confirmation gate applies automatically.
  - **No DELETE**: Splunk does not document the endpoint, so it is not built on an assumption.

### v1.13.1 (2026-07-16)
- 🐛 **#157 Custom Function reads told the truth about what SOAR actually returned** — the S1 live probe (8.5.0.248) showed the read tools silently misreporting facts an AI agent would then build on. Fixed: (1) the list projection omits `scm_id`/`inputs`/`outputs`, so per-function counts are now **omitted rather than reported as `0`/`null`** ("not returned" ≠ "none") and the response says so (`LIST_PROJECTION_SPARSE`); (2) `warnings`/`errors` are only reported when SOAR actually returns them — this build omits them on GET, so defaulting to `[]` claimed "no warnings" (`VALIDATION_DETAIL_UNAVAILABLE`); (3) `passed_validation` is `false` for *every* function on this build (including Splunk's own), so the warning now only fires when warnings/errors corroborate it; (4) a truncated list (e.g. 50 of 157) is now disclosed with a `name=`/`scm_id=` tip.
- ✨ `get_custom_function` additionally passes through the undocumented-but-real fields this build returns: **`is_read_only`** (the write-safety gate for the upcoming draft slice), `python_version`, `version`.

### v1.13.0 (2026-07-16)
- ✨ **#155 Custom Functions — read-only discovery (slice S1)** — three new READ tools (43 tools total: 33 read / 10 write): `list_custom_functions` (server-side `name=` search, never returns source), `get_custom_function` (metadata, inputs/outputs, SOAR's native validation result, associated playbooks; source only via explicit `include_source=true`, size-limited + `source_sha256`), and `detect_custom_function_capabilities` (read-only probe; **never write-probes**; anything not positively observed reports `unknown` rather than being assumed from documentation).
  - Verified against the official REST contract: `GET/POST /rest/custom_function`, `GET/POST /rest/custom_function/<id>` (update is **POST, not PUT** — no HTTP-client change needed). `commit_sha` is surfaced as the `revision` token for optimistic concurrency in the upcoming draft-write slice; `passed_validation`/`warnings`/`errors` and `playbooks` (associations) ride along on the object for free. **DELETE is not documented by Splunk** and is reported as `unknown`.

### v1.12.4 (2026-07-16)
- ✨ **#139 Policy Phase 4 — asset/identity enrichment** — the policy guard now derives **target tags from the case's artifacts** (CEF values matched against a config tag map, new `asset_context` section). Critical targets force 2-person **live**: e.g. a case artifact `dc01.corp` → `domain_controller` → `APPROVE_2PERSON`, even for an otherwise-`ALLOW` `Enrichment` playbook. Opt-in (only if `asset_context` is configured), fail-safe (no match / fetch error / no section ⇒ no tags, never relaxes the base gate). Completes epic #135.
- ✨ **#151 Policy visibility in diagnostics** — `diagnose_soar_mcp_environment` / the security posture now report `policy_enabled` and raise a `run_playbook_without_policy_gate` flag when `run_playbook` is enabled but the gate is off.

### v1.12.3 (2026-07-16)
- ✨ **#148 `run_playbook` by name** — `run_playbook` now accepts `playbook_name` as an alternative to `playbook_id`, so *"run playbook X"* works without the user hunting for a numeric ID. Resolution is **safe and never guesses**: a unique case-insensitive **exact** name match runs; 0 matches, name-not-unique, or substring-only matches are **refused with a candidate list** (name + ID). The name is resolved to its ID in `call_tool` **before the policy gate**, so a name invocation can never bypass the gate; name- and ID-invocations canonicalize to the same approval-token key. `playbook_id` wins if both are given.

### v1.12.2 (2026-07-16)
- 🐛 **#146 `list_playbooks` run-by-name** — resolving a playbook by name failed: the list capped at `max_results` (e.g. 50 of 427) with no search, and `active_only=true` (the old default) hid runnable-but-inactive playbooks. Now: new `name` argument → **server-side `_filter_name__icontains`** (searches *all* playbooks, not just the first page); `active_only` default flipped to **false** (a playbook runs by ID even when inactive); capped lists explicitly hint to use `name=`. Flow: `list_playbooks(name="X")` → ID → `run_playbook(ID)`.

### v1.12.1 (2026-07-16)
- ✨ **#144** — the policy layer is now togglable from the **asset-config UI** (checkbox *policy_enabled*), no more hand-editing `local/mcp.conf`. Consistent with `enable_test_harness` / `scoped_tokens_enabled`: the connector persists the checkbox to `local/asset_overrides.json` and the handler applies it per request (UI value takes precedence over `mcp.conf`; unset ⇒ `mcp.conf` fallback). Default off (backwards-compatible).

### v1.12.0 (2026-07-15)
- ✨ **#135 Policy layer (gated-autonomous `run_playbook`)** — an unbypassable SOC guard in `call_tool` (the single dispatch chokepoint), **opt-in** via `[policy] enabled` (default off, backwards-compatible). Every `run_playbook` is evaluated to one of **ALLOW / APPROVE_1CLICK / APPROVE_2PERSON / DENY** before dispatch. Category sets the base gate; risk can only escalate, never relax; unknown category ⇒ `default_gate` (fail-safe, never ALLOW). Data-driven `policy/policy_config.json` — categories are extensible without code changes.
  - **#136 (P1)** decision core + config + 12 unit tests.
  - **#137 (P2)** guard integration + audit (every decision logged, incl. ALLOW).
  - **#138 (P3)** distinct-approver approval workflow: held 1-click/2-person runs collect the required approval(s) and then execute. Approver identity = scoped-token `soar_user_id`; **two-person requires two different SOAR users (no self-approval)**; file-backed, fcntl-locked, single-use, TTL store (mirrors #50/#116/#127). Fail-safe: no scoped-token identity ⇒ held, never executed.
- 🧹 `local/` (per-instance runtime state) is now git-ignored.

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
