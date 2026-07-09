# SOAR MCP Server — Live Tools (v1.6.2)

## Read-only tools (enabled by default)

### Case & Incident Management
- `list_cases` — List cases with status/severity/label/owner/limit filters
- `get_case` — Full case details by ID
- `search_cases` — Keyword search across title, description, tags
- `list_artifacts` — List artifacts for a case
- `get_artifact` — Full artifact details by ID
- `list_case_notes` — List notes/comments on a case
- `list_users` — List SOAR users
- `get_soar_info` — SOAR platform version and health

### Playbook Operations (read)
- `list_playbooks` — List available playbooks with name, category, active status
- `get_playbook_run` — Status and results of a specific playbook run
- `list_action_runs` — Recent action runs with status and results

### Playbook-Discovery & Build (v1.6.0+, read)
- `list_apps` — Enumerate installed connectors (name, vendor, app_id)
- `list_assets` — Map configured assets to app IDs
- `get_action_schema` — Action parameters and output datapaths via /rest/app_action
- `export_playbook` — Export playbook as base64 gzip TAR (blockly golden template)

## Write tools (enabled by default — playbook-builder required)
- `run_playbook` — Trigger a playbook on a case
- `create_artifact` — Add an artifact/IOC to a case
- `import_playbook` — Import a base64-encoded gzip TAR playbook into SOAR VPE
- `create_container` — Create an isolated test container (double-gated: also requires enable_test_harness=true in mcp.conf)

## Write tools (analyst-facing — disabled by default)
- `add_case_note` — Add a note/comment to a case
- `update_case_status` — Change case status
- `update_case_severity` — Change case severity
- `update_case_owner` — Reassign a case

## Token scopes

### Read-only playbook-builder scope
Mint via `mint mcp token` action. Include: all 17 read tools + get_action_schema, export_playbook, list_apps, list_assets.
Exclude: all write tools.

### Write/self-test scope
Add to read scope: run_playbook, create_artifact, import_playbook, create_container.
Requires enable_test_harness=true in mcp.conf for create_container.
