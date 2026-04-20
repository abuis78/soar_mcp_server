# SOAR MCP Server - Live Tools

**Version**: Deployed on Claude.ai (April 20, 2026)  
**Status**: Read-only tools active

## Available Tools (11 READ-only)

### Case Management

#### `list_cases`
List SOAR cases (containers) with optional filters. Returns case ID, title, status, severity, owner, label, and tags.

**Parameters:**
- `status` (optional): Filter by status: open, closed, resolved, new, in_progress
- `severity` (optional): Filter by severity: high, medium, low, informational
- `label` (optional): Filter by case label/type (e.g. phishing, malware, incident)
- `owner` (optional): Filter by owner username
- `limit` (optional): Maximum number of cases to return (default: 20, max: 50)

#### `get_case`
Get full details of a specific SOAR case by ID. Returns title, description, status, severity, owner, tags, artifacts count, notes count, playbook runs, and all custom fields.

**Parameters:**
- `case_id` (required): The numeric SOAR container/case ID

#### `search_cases`
Search SOAR cases by keyword across title, description, and tags. Returns matching cases sorted by creation time (newest first).

**Parameters:**
- `query` (required): Search term to look for in case title and description
- `limit` (optional): Maximum number of results (default: 20)

#### `list_case_notes`
List all analyst notes and comments on a SOAR case. Returns note content, author, creation time.

**Parameters:**
- `case_id` (required): The SOAR container/case ID

---

### Artifact Management

#### `list_artifacts`
List all artifacts (IOCs, observables) associated with a SOAR case. Returns artifact ID, type, name, CEF fields (IP, domain, hash, URL, email, etc.), source, and creation time.

**Parameters:**
- `case_id` (required): The SOAR container/case ID to list artifacts for
- `artifact_type` (optional): Optional filter by CEF artifact type (e.g. ip, domain, hash, email, url)

#### `get_artifact`
Get full details of a specific artifact by ID. Returns all CEF fields, tags, source, and associated case.

**Parameters:**
- `artifact_id` (required): The numeric SOAR artifact ID

---

### Playbook & Automation

#### `list_playbooks`
List all available SOAR playbooks with name, description, category, and active status.

**Parameters:**
- `active_only` (optional): Return only active playbooks (default: true)
- `category` (optional): Optional filter by playbook category

#### `get_playbook_run`
Get the status and results of a specific playbook run. Returns run status (running, success, failed), start/end time, action results, and any output data.

**Parameters:**
- `run_id` (required): The SOAR playbook run ID

#### `list_action_runs`
List recent action runs for a case, showing what automated actions have been executed, their status, app used, and results.

**Parameters:**
- `case_id` (required): The SOAR container/case ID
- `limit` (optional): Maximum number of action runs to return (default: 20)

---

### System & Users

#### `list_users`
List SOAR users with username, display name, email, and role.

**Parameters:**
- `role` (optional): Optional filter by role name

#### `get_soar_info`
Get system information about this SOAR instance: version, license info, connected apps count, and overall health status.

**Parameters:** None

---

## Not Currently Active

The following WRITE tools are defined in the app configuration but **NOT enabled** in the live deployment:

- `add_case_note` - Add a note/comment to a case
- `create_artifact` - Add a new artifact/IOC to a case
- `run_playbook` - Trigger a SOAR playbook on a case
- `update_case_owner` - Reassign a case to a different analyst
- `update_case_severity` - Change the severity level of a case
- `update_case_status` - Change case status

---

## Usage Context

This MCP server is connected to **OpenClaw SOC** (Splunk SOAR instance) and accessible through:
- Claude Desktop (via MCP configuration)
- Claude.ai web interface (via connector integration)
- Claude Code (via MCP configuration)

**Security Model**: Read-only by default. Write operations require explicit asset configuration checkbox enablement in SOAR.
