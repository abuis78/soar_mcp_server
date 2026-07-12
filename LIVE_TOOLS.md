# SOAR MCP Server — Live Tools (v1.11.6)

**40 tools total: 30 read-only (enabled by default) + 10 write (off by default).**
Availability is controlled per-tool via the asset configuration checkboxes.

## Read-only tools (30 — enabled by default)

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
- `list_playbooks` — List available playbooks (name, category, active status, name_contains/limit filters)
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

### Diagnostics & Capability (v1.8.0+, read) (4)
- `generate_mcp_client_config` — Copy-ready MCP client config snippets (Claude Desktop/Code, Cursor, CLI); token is always a placeholder
- `diagnose_soar_mcp_environment` — Read-only environment diagnostics: app version, endpoint shape, handler reachability, `/rest/version` probe, security posture; `output_format=text|json`
- `detect_soar_capabilities` — Detect how this SOAR instance behaves (COA graph availability, export fallback, Python source, validation method)
- `audit_visual_playbook` — One-call pre-edit audit of a playbook (stale/current, counts, warnings/errors, trigger/type, Python source, validation + drift, recommendations); verdict pass/warn/fail/unknown

## Write tools (10 — OFF by default; enable deliberately via asset checkboxes)

### Playbook-build / self-test (5)
- `run_playbook` — Trigger a playbook on a case
- `create_artifact` — Add an artifact/IOC to a case
- `import_playbook` — Import a base64-encoded gzip TAR playbook into the SOAR VPE
- `create_container` — Create an isolated test container (double-gated: also requires `enable_test_harness=true`; default label configurable via `test_container_label`)
- `delete_container` — Delete a suite-owned test container (test-harness gated; suite-owned = configured label or `test_container_name_prefix`; 403 reported as a cleanup finding)

### Analyst-facing (4)
- `add_case_note` — Add a note/comment to a case (HTML stripped)
- `update_case_status` — Change case status (open/closed/resolved/new/in_progress)
- `update_case_severity` — Change case severity (high/medium/low/informational)
- `update_case_owner` — Reassign a case

### COA write (1, experimental — hidden from tools/list)
- `save_playbook_layout_only` — Save node x/y positions to the VPE; `dry_run=true` (default) previews without writing. The real write path is unverified, so the tool is **hidden from `tools/list`** until the COA write endpoint is confirmed (dry-run still works if called directly).

## Safety: two-step confirmation (optional)

Set `[safety] require_confirmation = true` to require a **two-step commit** for every write tool: the first call returns a `confirm_token` + preview, the second call (same args + token) executes. Tokens are persisted (`local/pending_confirmations.json`), single-use, TTL-bound, and survive SOAR's multi-process handler.

## Token scopes

### Read-only scope (recommended default)
Mint via the `mint mcp token` action. Include: all 30 read-only tools. Exclude: all 10 write tools.

### Playbook-builder / write scope
Add to the read scope, as needed: `run_playbook`, `create_artifact`, `import_playbook`, `create_container`, `delete_container`.
`create_container`/`delete_container` additionally require `enable_test_harness=true` (asset checkbox or `mcp.conf [safety]`).
