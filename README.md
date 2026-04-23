# SOAR MCP Server

**Splunk SOAR On-Premises App — v1.4.15**

Transform Splunk SOAR into an MCP (Model Context Protocol) server endpoint for direct AI integration. Claude Desktop, Claude Code, Claude.ai, or any MCP-compatible AI client can connect directly to your SOAR instance for structured access to cases, artifacts, playbooks, and analyst notes — completely on-premises, with zero external dependencies.

**Key Features:**
- ✅ **100% On-Premises** — No cloud services, no data exfiltration
- ✅ **Read-Only by Default** — 11 read tools active, 6 write tools opt-in
- ✅ **Asset-Based Configuration** — Control tool availability via SOAR UI checkboxes
- ✅ **AI Instructions Field** — Inject SOC-specific context into every AI session
- ✅ **Custom Widgets** — Built-in Config Builder with copy-paste snippets for Claude Desktop/Code
- ✅ **Audit Trail** — All tool calls logged via SOAR's native audit system

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
│  https://<your-soar>/rest/handler/phantom_soar_mcp_server/mcp │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  SOAR MCP Server App (Python REST Handler)           │  │
│  │  ├─ Tool Registry (asset config checkboxes)          │  │
│  │  ├─ AI Instructions Context Injection                │  │
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
│  │  ├─ Playbooks & Action Runs                           │  │
│  │  ├─ Notes & Analyst Comments                          │  │
│  │  └─ User & System Info                                │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Everything stays inside your network.** No calls to Anthropic or any cloud service. The AI client connects directly to your SOAR instance via authenticated HTTPS.

---

## Installation

### Step 1: Install the App

1. **Download** `soar_mcp_server_v1.4.15.tar` from this repository
2. In SOAR: **Apps → Install App** (top-right button)
3. **Upload** the TAR file
4. Click **Install** and wait for completion

The app installs immediately and the MCP endpoint becomes active at:
```
https://<your-soar>/rest/handler/phantom_soar_mcp_server/mcp
```

### Step 2: Configure the Asset

1. Navigate to **Apps → SOAR MCP Server → Asset Settings**
2. Click **Configure New Asset** (or edit the default asset)

**Required Configuration:**

| Field | Value | Purpose |
|-------|-------|---------|
| **Asset Name** | `soar_mcp_server` | Identifies this MCP server instance |
| **Base URL** | `https://soar.example.com` | Your SOAR instance URL (for Test Connectivity) |
| **Auth Token** | `ph-auth-token-xxx` | From **Administration → User Management → Users → [your user] → Authorization Tokens** |

**Optional Configuration:**

| Field | Default | Description |
|-------|---------|-------------|
| **AI Instructions** | _(empty)_ | Additional context sent to the AI on every MCP session. Use this to describe your SOAR environment, naming conventions, severity triage rules, escalation procedures, or any SOC-specific context the AI should know. Example: _"Cases labeled 'phishing' should always be escalated if severity is high. Owner format is firstname.lastname."_ |

**Tool Selection (Checkboxes):**

Enable/disable specific MCP tools via checkboxes in the asset configuration:

**READ Tools (default: enabled):**
- ✅ `list_cases` — List SOAR cases with status/severity/label/owner filters
- ✅ `get_case` — Get full details of a specific case by ID
- ✅ `search_cases` — Search cases by keyword across title and description
- ✅ `list_artifacts` — List all IOCs/observables attached to a case
- ✅ `get_artifact` — Get full details of a specific artifact by ID
- ✅ `list_case_notes` — List analyst notes and comments on a case
- ✅ `list_playbooks` — List available SOAR playbooks with name and description
- ✅ `get_playbook_run` — Get the status and results of a playbook run
- ✅ `list_action_runs` — List recent automated action runs on a case
- ✅ `list_users` — List SOAR users with roles and email addresses
- ✅ `get_soar_info` — Get SOAR version, build number, and installed app count

**WRITE Tools (default: disabled) ⚠️:**
- ⬜ `add_case_note` — Add a note/comment to a case
- ⬜ `create_artifact` — Add a new artifact/IOC to a case
- ⬜ `run_playbook` — Trigger a SOAR playbook on a case
- ⬜ `update_case_owner` — Reassign a case to a different analyst
- ⬜ `update_case_severity` — Change the severity level of a case
- ⬜ `update_case_status` — Change case status (open/closed/resolved/new/in_progress)

### Step 3: Test Connectivity

1. Click **Test Connectivity** in the asset configuration
2. Verify output shows:
   - ✅ MCP endpoint is reachable
   - ✅ Auth token is valid
   - ✅ Tool configuration applied successfully
   - ✅ Number of enabled tools

**The MCP server is now ready for Claude connections.**

---

## Connecting Claude

**Easiest Method:** Run the **Get MCP Config** action in SOAR — the custom widget generates ready-to-copy JSON snippets for Claude Desktop and Claude Code with your exact endpoint URL and auth token already filled in.

### Option 1: Claude Desktop (macOS/Windows)

**Config File Location:**
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

**Manual Configuration:**

1. Create/edit the config file
2. Add this JSON (replace placeholders):

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

3. **Save** and **restart Claude Desktop**
4. Verify connection: Look for "splunk-soar" in the bottom-left MCP server list

**Getting Your Auth Token:**
1. SOAR UI → **Administration → User Management → Users**
2. Click your username
3. Scroll to **Authorization Tokens** → **+ Token**
4. Copy the generated token

### Option 2: Claude Code (CLI)

**Quick Setup:**

```bash
claude mcp add splunk-soar \
  --transport http \
  --url "https://soar.example.com/rest/handler/phantom_soar_mcp_server/mcp" \
  --header "ph-auth-token: YOUR_SOAR_AUTH_TOKEN"
```

**Manual Config File (`~/.claude.json`):**

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

**Verify Connection:**

```bash
claude mcp list
# Should show: splunk-soar (connected)
```

### Option 3: Claude.ai (Web Interface)

**Prerequisites:**
- Enterprise Claude.ai subscription with MCP connector support
- SOAR instance accessible from the internet (or via VPN/proxy)

**Setup:**
1. Claude.ai → **Settings → Integrations → MCP Servers**
2. Click **+ Add Server**
3. Configure:
   - **Name**: `Splunk SOAR`
   - **URL**: `https://soar.example.com/rest/handler/phantom_soar_mcp_server/mcp`
   - **Auth Type**: `Custom Header`
   - **Header Name**: `ph-auth-token`
   - **Header Value**: `YOUR_SOAR_AUTH_TOKEN`
4. **Test Connection** → **Save**

**Security Note for Internet-Exposed SOAR:**
- Use a dedicated read-only SOAR user
- Enable IP allowlisting for Claude.ai IP ranges
- Rotate auth tokens regularly
- Monitor audit logs for suspicious activity

### Troubleshooting Connection Issues

| Issue | Solution |
|-------|----------|
| "Connection refused" | Verify SOAR REST endpoint is accessible: `curl -I https://soar.example.com/rest/handler/phantom_soar_mcp_server/mcp` |
| "Unauthorized" | Check auth token validity in SOAR UI → User Management |
| "SSL certificate verify failed" | Add SOAR's SSL cert to system trust store, or set `ssl_verify = false` in asset config (testing only) |
| "Server not responding" | Check SOAR logs: `/var/log/phantom/soar/phantom.log` and search for `soar_mcp_handler` |
| Tools not appearing | Run **Test Connectivity** in asset config to refresh tool registry |

---

## Available Tools

All tools are controlled via **asset configuration checkboxes** in the SOAR UI. Changes take effect immediately after running **Test Connectivity**.

### Read-Only Tools (Enabled by Default)

These 11 tools provide comprehensive read-only access to your SOAR instance:

| Tool | Parameters | Returns | Use Case |
|------|-----------|---------|----------|
| **`list_cases`** | `status`, `severity`, `label`, `owner`, `limit` | Array of cases with ID, title, status, severity, owner, tags | "Show me all high-severity phishing cases" |
| **`get_case`** | `case_id` | Full case detail: description, artifacts count, notes count, playbook runs, custom fields | "Get details for case 12345" |
| **`search_cases`** | `query`, `limit` | Cases matching keyword search (title + description) | "Find cases mentioning 'emotet'" |
| **`list_artifacts`** | `case_id`, `artifact_type` | Array of artifacts: ID, type, name, CEF fields (IP/domain/hash/URL/email), source | "List all IP addresses in case 12345" |
| **`get_artifact`** | `artifact_id` | Full artifact detail: all CEF fields, tags, source, associated case | "Get details for artifact 67890" |
| **`list_case_notes`** | `case_id` | Array of notes: content, author, timestamp | "Show analyst comments on case 12345" |
| **`list_playbooks`** | `active_only`, `category` | Array of playbooks: name, description, category, active status | "List all phishing response playbooks" |
| **`get_playbook_run`** | `run_id` | Playbook run status (running/success/failed), start/end time, action results | "Check if playbook run 555 completed" |
| **`list_action_runs`** | `case_id`, `limit` | Array of action runs: action name, app, status, results, timestamp | "What automated actions ran on case 12345?" |
| **`list_users`** | `role` | Array of users: username, display name, email, role | "List all analysts" |
| **`get_soar_info`** | _(none)_ | SOAR version, build number, license status, app count, system health | "What version of SOAR is this?" |

**Security Model:** Read tools operate within the SOAR user's permissions. The connected user must have appropriate role-based access to cases/artifacts/playbooks.

### Write Tools (Disabled by Default) ⚠️

These 6 tools modify live SOAR data and must be explicitly enabled via asset configuration checkboxes:

| Tool | Parameters | Action | Risk Level |
|------|-----------|--------|------------|
| **`add_case_note`** | `case_id`, `note_content` | Adds analyst note/comment to case | 🟡 Low — Audit trail preserved |
| **`create_artifact`** | `case_id`, `cef_type`, `cef_value`, `label`, `source` | Adds new IOC/observable to case | 🟡 Low — Can pollute case data |
| **`update_case_owner`** | `case_id`, `new_owner` | Reassigns case to different analyst | 🟠 Medium — Disrupts workflow |
| **`update_case_severity`** | `case_id`, `new_severity` | Changes severity (high/medium/low/informational) | 🟠 Medium — Affects SLA/priority |
| **`update_case_status`** | `case_id`, `new_status` | Changes status (open/closed/resolved/new/in_progress) | 🔴 High — Can close active investigations |
| **`run_playbook`** | `case_id`, `playbook_id` | Triggers automated playbook execution | 🔴 High — Can execute response actions |

**Best Practice:** Start with read-only tools. Enable write tools one-by-one after testing in a non-production environment. Always use a dedicated SOAR user with minimal required permissions.

### Tool Availability Reference

To check which tools are currently enabled for your Claude connection:
1. SOAR UI → **Apps → SOAR MCP Server → Asset Settings**
2. View checkbox states in the asset configuration
3. Or run the **Get MCP Config** action to see the active tool list

---

## Configuration Deep Dive

### Asset-Based Configuration (Recommended)

**v1.4.15 introduces asset-based configuration** via checkboxes in the SOAR UI. This is now the primary configuration method and survives app upgrades.

**Location:** SOAR UI → **Apps → SOAR MCP Server → Asset Settings → Configure Asset**

**Configuration Fields:**

| Field | Type | Purpose |
|-------|------|---------|
| **Base URL** | String | SOAR instance URL for Test Connectivity validation |
| **Auth Token** | Password | SOAR authorization token for Test Connectivity |
| **AI Instructions** | Text Area | Additional context injected into every MCP session. Use this to describe SOC-specific naming conventions, triage rules, escalation procedures, etc. |
| **Tool Checkboxes** | Boolean × 17 | Enable/disable each MCP tool individually (11 READ + 6 WRITE) |

**AI Instructions Examples:**

```
# Example 1: Naming Conventions
Cases labeled 'phishing' use format PHI-YYYY-NNNN.
Owner format is firstname.lastname.
Severity high = P1 response required within 1 hour.

# Example 2: Escalation Rules
Cases with severity=high and label=ransomware must be escalated to SOC Lead immediately.
After-hours escalations go through on-call rotation (check list_users for current on-call).

# Example 3: Playbook Context
'Enrich IP' playbook checks VirusTotal + AbuseIPDB + Shodan.
'Phishing Response' playbook auto-quarantines email + blocks sender domain.
Never run 'Block IP' playbook without analyst approval - it modifies firewall rules.
```

**Changes Take Effect:** Immediately after clicking **Test Connectivity**. No app restart required.

### File-Based Configuration (Legacy/Advanced)

For advanced users who prefer file-based config or need to override settings programmatically.

**File Location:**
```
/opt/phantom/apps/phantom_soar_mcp_server_<version>/
├── default/mcp.conf   ← Bundled defaults (do not edit)
└── local/mcp.conf     ← Your overrides (create this file)
```

**Override Precedence:** `local/mcp.conf` > `asset configuration` > `default/mcp.conf`

#### Example: Enabling Write Tools via File

Create `/opt/phantom/apps/phantom_soar_mcp_server_<version>/local/mcp.conf`:

```ini
[tools]
# Override asset checkboxes with file-based config
enable_add_case_note = true
enable_run_playbook = true
enable_update_case_status = false
enable_update_case_severity = false
enable_update_case_owner = false
enable_create_artifact = false
```

#### Example: Safety Settings

```ini
[safety]
# Prepend this disclaimer to all AI-generated content
advisory_disclaimer = ⚠️ AI-generated content. Verify before acting.

# Restrict tool usage to specific case labels (comma-separated)
# Empty = no restriction
allowed_labels = phishing,malware,incident

# Limit artifacts returned per case (prevents memory exhaustion)
max_items_per_case = 200

# Minimum severity for write operations (low|medium|high)
min_severity = medium
```

#### Full Configuration Reference

```ini
[server]
# Request timeout in seconds
timeout = 30

# Maximum results returned by list_* tools
max_results = 50

# Verify SSL certificates (set false only for self-signed certs in test environments)
ssl_verify = true

# Log all tool calls to SOAR audit trail
log_tool_calls = true

# MCP protocol version
protocol_version = 2024-11-05

# Server metadata exposed to MCP clients
server_name = Splunk SOAR MCP Server
server_version = 1.4.15

[tools]
# READ Tools (default: enabled)
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

# WRITE Tools (default: disabled)
enable_add_case_note = false
enable_run_playbook = false
enable_update_case_status = false
enable_update_case_severity = false
enable_update_case_owner = false
enable_create_artifact = false

[safety]
advisory_disclaimer = ⚠️ AI-generated content. Verify before acting.
allowed_labels = 
max_items_per_case = 200
min_severity = low

[logging]
# Log level: DEBUG, INFO, WARNING, ERROR
level = INFO

# Log file location (empty = stdout only)
log_file = 

# Include request/response payloads in logs (verbose, sensitive data)
log_payloads = false
```

**Applying File Changes:**
1. Edit `local/mcp.conf`
2. Run **Test Connectivity** in asset configuration to reload
3. Changes take effect immediately (no restart required)

---

## Security & Best Practices

### Authentication & Authorization

**Dedicated SOAR User (Recommended):**
1. Create a service account: `mcp_claude_readonly`
2. Assign minimal role: **Analyst (Read-Only)** or custom role with limited permissions
3. Generate auth token for this user only
4. Use this token in Claude Desktop/Code/Web config
5. **Never use admin tokens for MCP connections**

**Token Management:**
- Rotate tokens every 90 days
- Store tokens in secure credential manager (1Password, Bitwarden, etc.)
- Never commit tokens to version control
- Monitor token usage via SOAR audit logs

**Role-Based Access Control:**
- Claude inherits the connected user's SOAR permissions
- Read tools respect case visibility (label-based access)
- Write tools respect role capabilities (e.g., only owners can close cases)

### Network Security

**On-Premises Deployment (Recommended):**
```
┌──────────────────┐          ┌──────────────────┐
│  Claude Desktop  │  ─────→  │  SOAR (Internal) │
│  (Laptop/VPN)    │  HTTPS   │  10.x.x.x        │
└──────────────────┘          └──────────────────┘
```
- SOAR remains internal-only
- Claude Desktop connects via VPN
- Zero external exposure

**Internet-Exposed Deployment (Enterprise Only):**
```
┌──────────────────┐          ┌──────────────────┐          ┌──────────────────┐
│  Claude.ai Web   │  ─────→  │  Reverse Proxy   │  ─────→  │  SOAR (DMZ)      │
│  (Cloud)         │  HTTPS   │  + WAF + IP ACL  │  HTTPS   │  Public IP       │
└──────────────────┘          └──────────────────┘          └──────────────────┘
```
**Required Protections:**
- WAF (Web Application Firewall) with rate limiting
- IP allowlisting for Claude.ai IP ranges (request from Anthropic)
- TLS 1.3 with strong cipher suites
- DDoS protection
- API gateway with request throttling

**Firewall Rules:**
```bash
# Allow Claude.ai → SOAR (if internet-exposed)
iptables -A INPUT -p tcp --dport 443 -s <claude-ai-ip-range> -j ACCEPT

# Deny all other external access to SOAR
iptables -A INPUT -p tcp --dport 443 -j DROP
```

### Audit & Monitoring

**Enable Full Audit Logging:**

In `local/mcp.conf`:
```ini
[server]
log_tool_calls = true

[logging]
level = INFO
log_payloads = false  # Set true only for debugging (exposes sensitive data)
```

**What Gets Logged:**
- Every MCP tool call (tool name, parameters, timestamp, user)
- Tool execution duration
- Success/failure status
- Error messages (but not full payloads by default)

**Log Locations:**
- SOAR audit trail: **Administration → System Health → Logs → phantom.log**
- App-specific logs: `/var/log/phantom/soar/phantom.log` (search for `soar_mcp_handler`)

**Monitoring Queries (Splunk):**

```spl
# High-volume tool usage (potential abuse)
index=soar sourcetype=phantom:log "soar_mcp_handler"
| stats count by user, tool_name
| where count > 100
| sort -count

# Failed authentication attempts
index=soar sourcetype=phantom:log "soar_mcp_handler" "authentication failed"
| stats count by src_ip, user

# Write operations (if write tools enabled)
index=soar sourcetype=phantom:log "soar_mcp_handler" tool_name IN (add_case_note, run_playbook, update_case_status, create_artifact)
| table _time, user, tool_name, case_id, result
```

### Write Tool Safety

**Graduated Enablement Strategy:**

| Phase | Enabled Tools | Risk | Use Case |
|-------|---------------|------|----------|
| **Phase 1 (Pilot)** | READ only (11 tools) | 🟢 Minimal | Investigation support, case search, artifact lookup |
| **Phase 2 (Controlled Write)** | READ + `add_case_note` | 🟡 Low | AI-assisted analyst commentary, investigation summaries |
| **Phase 3 (Enrichment)** | Phase 2 + `create_artifact` | 🟡 Low | AI-extracted IOCs from reports/emails |
| **Phase 4 (Workflow)** | Phase 3 + `update_case_owner`, `update_case_severity` | 🟠 Medium | AI-suggested triage/assignment (human approval required) |
| **Phase 5 (Orchestration)** | Phase 4 + `run_playbook`, `update_case_status` | 🔴 High | Full AI-driven response (strict guardrails required) |

**Guardrails for Write Tools:**

```ini
[safety]
# Require human approval for high-impact operations
min_severity = high  # Write tools only work on high/critical cases

# Restrict to specific case types
allowed_labels = phishing,malware  # Block write on 'incident' or 'forensics' cases

# Limit blast radius
max_items_per_case = 50  # Prevent runaway artifact creation
```

**Human-in-the-Loop Pattern:**

```python
# Example: AI suggests action, analyst approves
Claude: "I recommend running the 'Enrich IP' playbook on case 12345."
Analyst: [Reviews case context, approves]
Claude: [Calls run_playbook tool]
SOAR: [Executes playbook, logs action with analyst approval reference]
```

### SSL/TLS Configuration

**Production (Recommended):**
```ini
[server]
ssl_verify = true
```
Use trusted CA certificates. SOAR's SSL cert must be in the system trust store.

**Testing/Self-Signed Certs (Non-Production Only):**
```ini
[server]
ssl_verify = false
```
⚠️ **Never disable SSL verification in production.** Use proper certificates.

### Data Privacy

**What Data Claude Sees:**
- Case metadata (title, description, status, severity, owner, tags)
- Artifact data (IOC values, CEF fields)
- Analyst notes (comments, investigation findings)
- Playbook/action run results

**What Claude Does NOT See:**
- SOAR user passwords or auth tokens
- Credential vault secrets
- Playbook source code (only playbook names/descriptions)
- System configuration files

**Data Residency:**
- **Claude Desktop/Code**: All data stays on-premises (Claude runs locally)
- **Claude.ai Web**: MCP requests transit to Anthropic cloud (see [Anthropic's data retention policy](https://www.anthropic.com/legal/privacy))

**Sensitive Data Handling:**
- Never include PII (SSN, credit cards, health records) in case descriptions
- Redact sensitive data before running playbooks that log output
- Use SOAR's data masking features for compliance (GDPR, HIPAA, PCI-DSS)

### Incident Response

**If MCP Token Compromised:**
1. Immediately revoke token in SOAR: **User Management → [user] → Authorization Tokens → Delete**
2. Review audit logs for unauthorized activity
3. Generate new token and update Claude configs
4. Notify security team

**If Unauthorized Write Operations Detected:**
1. Disable write tools via asset config: **Apps → SOAR MCP Server → Uncheck write tool boxes → Test Connectivity**
2. Review `phantom.log` for source IP, timestamp, affected cases
3. Roll back changes if needed (SOAR tracks all modifications)
4. Investigate how the AI was prompted to perform unauthorized actions

## Use Cases & Examples

### 1. AI-Assisted Investigation

**Scenario:** Analyst receives a high-volume phishing campaign alert and needs to quickly triage 50 related cases.

**Claude Workflow:**
```
Analyst: "Show me all open phishing cases from the last 24 hours with high severity"
Claude: [Calls list_cases with filters] → Returns 23 cases
Claude: "Here are 23 high-priority phishing cases. The most common indicators are:
         - 12 cases target finance@company.com
         - 8 cases use lookalike domain 'microsfot.com'
         - 5 cases contain Emotet payload hashes"

Analyst: "Get details on case 12345"
Claude: [Calls get_case] → Returns full case detail
Claude: "Case 12345 'Credential Phishing - CFO Impersonation':
         - 3 email artifacts
         - 2 domain artifacts (phishing[.]example[.]com, evil[.]com)
         - Analyst notes indicate active C2 communication"

Analyst: "List all artifacts and cross-reference with other cases"
Claude: [Calls list_artifacts for case 12345, then searches other cases]
Claude: "The domain phishing[.]example[.]com appears in 8 other cases.
         Recommend pivoting investigation to cases: 12346, 12350, 12355..."
```

**Time Saved:** 15 minutes of manual SOAR UI navigation → 2 minutes of natural language queries

### 2. Automated Case Enrichment (Write Tools)

**Scenario:** Threat intel feed identifies a new IOC (IP address) tied to an ongoing campaign. Add it to all related cases.

**Claude Workflow (with `create_artifact` enabled):**
```
Analyst: "Search for cases mentioning 'APT29' in the last 7 days"
Claude: [Calls search_cases] → Returns 5 cases

Analyst: "Add the IP 192.0.2.123 as an artifact to all 5 cases with source 'ThreatConnect Feed'"
Claude: [Confirms] "I'll add IP artifact 192.0.2.123 to cases 12345, 12346, 12347, 12348, 12349. Proceed?"
Analyst: "Yes"
Claude: [Calls create_artifact 5 times] → Success
Claude: "Added IP artifact to all 5 cases. Each artifact is tagged 'threatconnect' and labeled 'indicator'."
```

**Time Saved:** 5 cases × 3 clicks per case (15 clicks) → 1 confirmation

### 3. Playbook Orchestration (Advanced)

**Scenario:** Run enrichment playbooks on all new cases automatically during triage.

**Claude Workflow (with `run_playbook` enabled):**
```
Analyst: "List all new phishing cases without playbook runs"
Claude: [Calls list_cases + get_playbook_run for each] → Identifies 12 cases

Analyst: "Run the 'Enrich Phishing' playbook on all 12 cases"
Claude: [Confirms] "This will trigger 12 playbook executions. Each playbook:
         - Checks VirusTotal for URL reputation
         - Queries WHOIS for domain registration
         - Extracts email headers
         Estimated runtime: 5 minutes per case. Proceed?"
Analyst: "Yes, but only on cases with severity >= medium"
Claude: [Filters to 8 cases, calls run_playbook] → Success
Claude: "Playbooks started on 8 cases. Monitoring runs...
         - Case 12345: Completed (3 malicious URLs found)
         - Case 12346: Running...
         - Case 12347: Completed (domain registered yesterday, suspicious)"
```

**Time Saved:** Manual playbook triggering (8 cases × 2 minutes) = 16 minutes → Automated

### 4. Executive Reporting

**Scenario:** CISO requests a summary of Q1 incident response metrics.

**Claude Workflow:**
```
Analyst: "Generate a Q1 summary report: total cases, breakdown by severity and status, average resolution time"
Claude: [Calls list_cases with date filters, aggregates data]
Claude: "Q1 2026 Incident Response Metrics:
         Total Cases: 487
         By Severity: High (23), Medium (145), Low (319)
         By Status: Closed (412), Open (52), In Progress (23)
         By Label: Phishing (201), Malware (89), Incident (45), Other (152)
         
         Average Resolution Time:
         - High Severity: 4.2 hours
         - Medium Severity: 18.7 hours
         - Low Severity: 2.3 days
         
         Top Playbooks Used: 'Enrich Phishing' (156 runs), 'Block IP' (78 runs)"
```

**Time Saved:** Manual Excel pivot tables + SOAR API queries (30 minutes) → 30 seconds

### 5. Threat Hunting

**Scenario:** Hunt for lateral movement indicators across all cases.

**Claude Workflow:**
```
Analyst: "Search all cases for artifacts with type=hash and cef_value matching known Mimikatz signatures"
Claude: [Calls list_cases, then list_artifacts for each with artifact_type filter]
Claude: "Found 3 cases with Mimikatz artifacts:
         - Case 12340: 2 artifacts (mimikatz.exe SHA256, sekurlsa.dll MD5)
         - Case 12355: 1 artifact (procdump.exe SHA1 - Mimikatz renamed)
         - Case 12389: 3 artifacts (custom Mimikatz build, obfuscated)
         
         All 3 cases involve Domain Admin account compromise.
         Recommend immediate review of cases 12340, 12355, 12389."
```

**Time Saved:** Manual artifact correlation across 487 cases (1+ hours) → 1 minute

---

## Standalone Testing (without SOAR)

For development/testing without a live SOAR instance, the app includes a standalone mode with mock data.

**Start Mock Server:**

```bash
cd /opt/phantom/apps/phantom_soar_mcp_server_<version>/
python3 soar_mcp_handler.py --host 127.0.0.1 --port 8743 --mock
```

**Mock Data Includes:**
- 10 sample cases (various statuses/severities)
- 25 artifacts (IP/domain/hash/email/URL)
- 5 playbooks
- 3 users

**Test with curl:**

```bash
# MCP tools/list request
curl -X POST http://127.0.0.1:8743 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# Call list_cases
curl -X POST http://127.0.0.1:8743 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_cases","arguments":{"status":"open"}}}'
```

**Test with Claude Desktop:**

```json
{
  "mcpServers": {
    "soar-mock": {
      "url": "http://127.0.0.1:8743"
    }
  }
}
```

---

## Roadmap

**v1.5.x (Planned - Q2 2026):**
- [ ] Batch operations (update multiple cases at once)
- [ ] Custom field support in `list_cases` filters
- [ ] Artifact deduplication across cases
- [ ] Playbook parameter injection (pass args to playbook runs)
- [ ] WebSocket transport for long-running operations

**v1.6.x (Planned - Q3 2026):**
- [ ] SOAR Evidence Vault integration (attach files to cases)
- [ ] Advanced search with boolean operators (AND/OR/NOT)
- [ ] Case timeline export (JSON/CSV)
- [ ] Integration with Splunk Enterprise Security (Notable Events → Cases)

**v2.0.x (Planned - Q4 2026):**
- [ ] Multi-tenancy support (partition tools by SOAR label/owner)
- [ ] AI-driven case prioritization (ML-based severity prediction)
- [ ] Natural language playbook generation (describe response → auto-build playbook)

**Community Requests:** Submit feature requests via GitHub Issues

---

## Troubleshooting

### Common Issues

| Symptom | Cause | Fix |
|---------|-------|-----|
| "Connection refused" | SOAR REST endpoint not accessible | `curl -I https://soar.example.com/rest/handler/phantom_soar_mcp_server/mcp` |
| "Unauthorized" | Invalid auth token | Regenerate token in SOAR UI → User Management |
| "SSL certificate verify failed" | Self-signed cert not trusted | Add cert to trust store or set `ssl_verify = false` (testing only) |
| Tools not appearing in Claude | Asset config not applied | Run **Test Connectivity** to refresh tool registry |
| "Tool disabled" error | Tool checkbox unchecked in asset | Enable tool via asset config → Test Connectivity |
| Empty results from `list_cases` | User lacks case visibility | Check SOAR role permissions (label-based access) |
| Playbook won't run | Playbook inactive or user lacks role | Verify playbook status in SOAR → Playbooks page |

### Debug Mode

Enable verbose logging:

```ini
[logging]
level = DEBUG
log_payloads = true  # ⚠️ Exposes sensitive data in logs
```

Check logs:
```bash
tail -f /var/log/phantom/soar/phantom.log | grep soar_mcp_handler
```

### Performance Tuning

**For large SOAR instances (10,000+ cases):**

```ini
[server]
timeout = 60  # Increase for slow SOAR responses
max_results = 100  # Return more results per query

[safety]
max_items_per_case = 500  # Allow more artifacts per case
```

**For rate-limited environments:**

```ini
[server]
# Add request throttling (future feature)
rate_limit_per_minute = 60
```

---

## Contributing

**Bug Reports:**
- GitHub Issues: https://github.com/abuis78/soar_mcp_server/issues
- Include: SOAR version, app version, error message, `phantom.log` excerpt

**Feature Requests:**
- Submit via GitHub Issues with `[FEATURE]` tag
- Describe use case, expected behavior, mockup/example

**Pull Requests:**
- Fork → branch → commit → PR
- Include unit tests for new tools
- Update `LIVE_TOOLS.md` with new tool documentation

**Development Setup:**

```bash
git clone https://github.com/abuis78/soar_mcp_server.git
cd soar_mcp_server

# Create test environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run tests
pytest tests/

# Start mock server
python3 soar_mcp_handler.py --mock --port 8743
```

---

## Changelog

### v1.4.15 (2026-04-20)
- ✨ Asset-based configuration with UI checkboxes
- ✨ AI Instructions field for SOC-specific context injection
- ✨ Custom Config Builder widget with copy-paste snippets
- 🐛 Fixed SSL verification for self-signed certificates
- 🐛 Fixed pagination for large case lists
- 📝 Added comprehensive LIVE_TOOLS.md documentation

### v1.3.0 (2026-03-20)
- ✨ Initial public release
- ✨ 11 read-only tools (cases, artifacts, playbooks, users)
- ✨ 6 write tools (add note, run playbook, update case fields)
- ✨ File-based configuration (`mcp.conf`)
- ✨ Standalone mock mode for testing

---

## Credits

**Author:** Andreas Buis ([@abuis78](https://github.com/abuis78))  
**Organization:** originvibe
**Created With:** Claude (Anthropic) — model `claude-sonnet-4-6`

**Special Thanks:**
- Splunk SOAR Engineering Team (REST handler architecture guidance)
- Anthropic MCP Team (protocol specification & testing support)
- OpenClaw SOC Community (beta testing & feedback)

---

## License

Copyright 2026 Andreas Buis. All rights reserved.

**Splunk SOAR App License:**
- Free for Splunk SOAR customers
- May not be redistributed or resold
- No warranty provided (use at your own risk)
- Source code provided for transparency and customization

**Splunk and SOAR are trademarks of Splunk Inc.**

---

## Support

**Community Support:**
- GitHub Issues: https://github.com/abuis78/soar_mcp_server/issues
- GitHub Discussions: https://github.com/abuis78/soar_mcp_server/discussions

**Enterprise Support:**
- Contact: support@originvibe.de
- Subject: "[SOAR MCP] Your Issue Here"
- Include: SOAR version, app version, logs, use case description

**Splunk Support:**
- This is a community-developed app, not officially supported by Splunk
- For SOAR platform issues, contact Splunk Support directly
- For MCP app issues, use GitHub channels above

---

**⭐ If you find this useful, please star the repo!**

**🐛 Found a bug? Open an issue.**

**💡 Have an idea? Submit a feature request.**
