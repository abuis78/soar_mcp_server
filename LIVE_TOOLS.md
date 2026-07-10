# SOAR MCP Server — Live Tools (v1.7.0)

**35 tools total: 26 read-only (enabled by default) + 9 write (off by default).**
Availability is controlled per-tool via the asset configuration checkboxes.

## Read-only tools (26 — enabled by default)

### Case & Incident Management (8)
- `list_cases` — List cases with status/severity/label/owner/limit filters
- `get_case` — Full case details by ID
- `search_cases` — Keyword search across title, description, tags
- `list_artifacts` — List artifacts for a case
- `get_artifact` — Full artifact details by ID
- `list_case_notes` — List notes/comments on a case
- `list_users` — List SOAR users
- `get_soar_info` — SOAR platform version and health

### Playbook Operations (read) (3)
- `list_playbooks` — List available playbooks with name, category, active status
- `get_playbook_run` — Status and results of a specific playbook run
- `list_action_runs` — Recent action runs with status and results

### Playbook-Discovery & Build (v1.6.0+, read) (4)
- `list_apps` — Enumerate installed connectors (name, vendor, app_id)
- `list_assets` — Map configured assets to app IDs
- `get_action_schema` — Action parameters and output datapaths via /rest/app_action
- `export_playbook` — Export playbook as base64 gzip TAR (blockly golden template)

### COA Visual Editor (v1.6.3+, read) (11)
- `resolve_playbook_current_id` — Resolve any playbook ID (current or stale) to the current VPE draft
- `get_playbook_identity_map` — Full revision chain for a playbook with the current draft marked
- `get_playbook_coa_summary` — Compact COA graph summary (nodes, edges, warnings, input/output spec)
- `list_playbook_nodes` — Structured list of COA nodes (type, position, optional redacted parameters)
- `list_playbook_edges` — Structured list of COA edges (source, target, branch conditions)
- `check_saved_generated_python_drift` — Detect helper functions in saved Python absent from COA userCode
- `check_datapath_selectability` — Schema-based check whether a producer datapath is selectable for a consumer parameter
- `diff_playbook_versions` — Semantic diff between two revisions (layout/metadata/graph/parameter/code/validation)
- `verify_layout_only_change` — Strict pass/fail that only x/y positions changed (gate for save_playbook_layout_only)
- `validate_playbook_bundle` — Multi-check validation (passed_validation, node warnings, py_compile, lint)
- `check_visual_editor_compat` — Aggregator: resolve + summary + nodes + drift + validation → ok/warn/fail

## Write tools (9 — OFF by default; enable deliberately via asset checkboxes)

### Playbook-build / self-test (4)
- `run_playbook` — Trigger a playbook on a case
- `create_artifact` — Add an artifact/IOC to a case
- `import_playbook` — Import a base64-encoded gzip TAR playbook into the SOAR VPE
- `create_container` — Create an isolated test container (double-gated: also requires `enable_test_harness=true`)

### Analyst-facing (4)
- `add_case_note` — Add a note/comment to a case
- `update_case_status` — Change case status (open/closed/resolved/new/in_progress)
- `update_case_severity` — Change case severity (high/medium/low/informational)
- `update_case_owner` — Reassign a case

### COA write (1, experimental)
- `save_playbook_layout_only` — Save node x/y positions to the VPE; `dry_run=true` (default) previews without writing

## Token scopes

### Read-only scope (recommended default)
Mint via the `mint mcp token` action. Include: all 26 read-only tools.
Exclude: all 9 write tools.

### Playbook-builder / write scope
Add to the read scope, as needed: `run_playbook`, `create_artifact`, `import_playbook`, `create_container`.
`create_container` additionally requires `enable_test_harness=true` (asset checkbox or `mcp.conf [safety]`).
