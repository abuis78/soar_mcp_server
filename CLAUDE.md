# CLAUDE.md — soar_mcp_server

Project rules only. The global `~/.claude/CLAUDE.md` applies in full; nothing here overrides it.

## Purpose
A Splunk SOAR app that exposes SOAR (cases, artifacts, notes, playbooks) as an MCP server.
Includes a policy layer (principal types, agent read gate, Policy Manager `service` mode,
approvals / `approve_action`, broker tokens).

## Stack
- Python 3.13 (`python_version` in `soar_mcp_server.json`), SOAR >= 8.5.0, live target SOAR 8.7.
- Standard library `unittest`; no extra test dependencies.
- App metadata: `soar_mcp_server.json` (`app_version`, `utctime_updated`).

## Commands
- Tests: `python3 -m unittest discover -s . -p 'test_*.py' > <scratch>/tests.log 2>&1`,
  then check for `Ran N tests` + `OK` in the file (current baseline: 488).
- Package (from a clean `HEAD`):
  1. `git archive --prefix=soar_mcp_server/ HEAD | tar -x -C <tmp>`
  2. In `<tmp>/soar_mcp_server`, delete `releases scripts .github .gitignore test_*.py CLAUDE.md`.
  3. `COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata -czf releases/soar_mcp_server_v<ver>.tar -C <tmp> soar_mcp_server`
  4. `python3 scripts/lint_soar_app_package.py releases/soar_mcp_server_v<ver>.tar`
  5. `git add -f releases/soar_mcp_server_v<ver>.tar`
- Release: bump `app_version` + README changelog, commit the package, PR, merge, then
  tag `v<ver>` and `gh release create v<ver>` with asset name `soar_mcp_server-<ver>.tar`.

## Status (2026-11-16)
- SPEC-MCP rebuild done (phases 1–4, v1.15.0–v1.18.2). Current: v1.19.0 (`approval_playbook`), live.
- Next, conditional:
  - Swap `policy/client.py` for the `policy_client` wheel once PolicyManager P3 ships `ServicePolicyClient`.
  - End-to-end test of `pm_freigabe`: needs the role `SOC-Freigabe` and the asset `pm_approve` on SOAR-Prod (setup side).
  - Service mode: needs the MCP client cert (one CN, EC P-256, clientAuth) and the PM entries
    `[clients] "soar-mcp" = ["decide"]`, `[principals] "soar-mcp" = ["mensch","agent"]`.

## Dependencies on other repos
- PolicyManager: wire format and `policy_client` wheel; `[playbook_categories]` keyed by numeric playbook id as a digit string.
- Setup repo: SOAR roles, assets, and certificates for service mode.

## Domain rules / lessons learned
- Approval tokens are never stored or logged in clear text. Logs, errors, and audit args carry only
  `freigabe_ref` / `approval_ref` = `sha256(id)[:16]`. This includes the handler audit args.
- The `approval_playbook` value is the bare playbook name (not `repo/name`). `playbook_run` needs a numeric
  `playbook_id` and `inputs` as a JSON object; a string gives HTTP 400 on SOAR 8.7.
- Starting the approval playbook is not fail-open: if the start fails, the hold stands.
- Every SOAR install wipes `local/`. Run Test Connectivity on the asset after each install, which restores
  the base URL and the tool overrides.
- `run_playbook` resolves `playbook_name` to an int `playbook_id` before any gate.
- With SOAR Multi-Tenancy on, write calls without a tenant may fail with HTTP 400.
- The project name of the overall SOC programme must not appear in docs or releases of this repo.
- Check `main` after every merge; stacked PRs do not retarget automatically.

## Control
This session is steered by the orchestrator session. Status reports and questions go to it via SendMessage.
Red items (global L1) still go to Andreas directly in this session.
