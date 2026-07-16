# Policy Layer — Gated-Autonomous `run_playbook`

> Since **v1.12.0**. Opt-in, default **off**, fully backwards-compatible.
> UI toggle since **v1.12.1** · works with run-by-name since **v1.12.3**.

The policy layer is an **unbypassable SOC guard** that sits in front of the single
execution chokepoint (`run_playbook`) and decides, for every run, whether the AI
may act autonomously or must first obtain human approval. It turns "AI can run
playbooks" into **graded autonomy**: safe enrichment runs on its own, response
actions are held for one or two humans, and anything unknown fails safe.

---

## 1. Where it sits (and why it can't be bypassed)

Every MCP tool call — regardless of client — is dispatched through **one** function,
`call_tool()` in [`soar_mcp_tools.py`](../soar_mcp_tools.py). That is also where the
existing two-step confirmation gate (#50) lives. The policy guard is evaluated
there, **before** the tool handler runs:

```
MCP client → REST handler → call_tool()
                              ├─ resolve playbook_name → playbook_id   (#148, pre-gate)
                              ├─ _policy_gate()   ← POLICY DECISION HERE
                              ├─ _maybe_require_confirmation()  (#50)
                              └─ tool handler (actually runs the playbook)
```

There is no code path to `run_playbook` that skips `call_tool()`, so there is no
path that skips the policy guard. A **name**-based invocation is resolved to its ID
*before* the gate (#148), so calling by name cannot bypass the decision either.

The guard only acts when **`policy_enabled = true`** and only on **`run_playbook`**
(the sole execution tool). All other tools are untouched.

---

## 2. The four gates

| Gate | Meaning | Effect on `run_playbook` |
|------|---------|--------------------------|
| `ALLOW` | Autonomous | Runs immediately (decision still audited) |
| `APPROVE_1CLICK` | One reviewer | Held until **one** human approves |
| `APPROVE_2PERSON` | Two reviewers | Held until **two different** humans approve |
| `DENY` | Blocked | Never runs |

Gates are ordered `ALLOW < APPROVE_1CLICK < APPROVE_2PERSON < DENY`. The final gate is
the **strictest** of three independent signals — risk can only *raise* the gate,
never lower it:

```
final_gate = max(base_gate, risk_gate, target_override)
```

---

## 3. The decision algorithm

Implemented in `PolicyLayer.evaluate()` in
[`policy/policy_layer.py`](../policy/policy_layer.py).

### 3a. Base gate — from the playbook **category**
The guard fetches the playbook's `category` (`GET playbook/{id}`) and looks it up in
`policy_config.json → categories`. **If the category is unknown or empty, the base
gate is `default_gate` (`APPROVE_2PERSON`) — never `ALLOW`.** This is the core
fail-safe: a new/unmapped category is held, not auto-run.

### 3b. Risk score — can only escalate
A `0..1` risk score is computed from three weighted inputs:

```
risk = w.asset_criticality · asset_criticality
     + w.reversibility     · (0 if reversible else 1)
     + w.low_confidence    · (1 − agent_confidence)
```

Default weights: `asset_criticality 0.5`, `reversibility 0.3`, `low_confidence 0.2`.
The score escalates the gate via thresholds:

| Risk score | Risk gate |
|------------|-----------|
| `≥ 0.67` (`to_2person`) | `APPROVE_2PERSON` |
| `≥ 0.34` (`to_1click`) | `APPROVE_1CLICK` |
| below | `ALLOW` (no escalation) |

### 3c. Target override — critical assets/identities force 2-person
If the action targets an asset or identity carrying a "crown-jewel" tag
(`always_2person_targets`), the override is `APPROVE_2PERSON` regardless of category.

### Worked example (the shipped default)
A `Containment` playbook → base `APPROVE_2PERSON`; even with perfect confidence and
zero criticality the risk gate is `ALLOW`, but `max(2PERSON, ALLOW, …) = 2PERSON`.
It is **held for two approvers** — exactly what a host-isolation action should require.

> **Honest scope (as of v1.12.3):** in the live path the guard currently populates
> only **category** (→ base gate) and `agent_confidence` (default `0.5`).
> `asset_criticality` and the target tags are **not yet sourced from live SOAR data**,
> so risk-escalation and the target override are dormant in production until
> **Phase 4 (#139)** wires an asset/identity tag map. The base-gate + fail-safe path
> is fully active and is what governs runs today.

---

## 4. Approval workflow (1-click / 2-person)

When a run is gated `APPROVE_1CLICK`/`APPROVE_2PERSON`, execution is **held** and the
guard returns an `approval_token`. Approvers re-call `run_playbook` with the **same
arguments plus the token**:

- **Approver identity** = the scoped-token `soar_user_id`. Without a scoped token
  there is **no accountable approver → the run stays held** (fail-safe).
- **1-click:** one valid approval → runs.
- **2-person:** two approvals from **two different** `soar_user_id`s → runs.
  The same user approving twice is rejected (**no self-approval**).
- The token store is **file-backed** (survives SOAR's multi-process handler),
  **`fcntl`-locked**, **single-use** on completion, and **TTL-bound** (10 min).
  Only a SHA-256 hash of the token is stored — never the raw token.

Implemented in [`policy/approvals.py`](../policy/approvals.py) (mirrors the #50/#116/#127
confirm-store discipline).

### Enabling real approvals
Approvals need scoped tokens:
1. Asset config → check **`scoped_tokens_enabled`** → Save → Test Connectivity.
2. Mint one token per approver with the **`mint mcp token`** action
   (`soar_user_id = alice`, `= bob`, …).
3. Each approver's MCP client uses its own token.

Until then, gated runs simply stay held (safe).

---

## 5. Enabling the policy layer

**Recommended — asset-config UI checkbox (v1.12.1+):**
SOAR → Assets → *your MCP asset* → Asset Settings → check **`policy_enabled`**
(and **`tool_run_playbook`**) → **Save** → **Test Connectivity**.

**Advanced — file-based** (`local/mcp.conf`):
```ini
[tools]
run_playbook = true
[policy]
enabled = true
```
The UI checkbox takes precedence over `mcp.conf`; if the checkbox is unset the
`mcp.conf` value is used.

> **MCP tool-list cache:** MCP clients read `tools/list` only at connect time.
> After installing/upgrading the app, **reconnect/restart your MCP client once** so
> it picks up new parameters (e.g. `playbook_name`) and behaviour.

---

## 6. Configuration reference — `policy/policy_config.json`

Data-driven: extend categories **without code changes**. Align the category keys
against your instance's real `list_playbooks` categories.

| Key | Purpose |
|-----|---------|
| `default_gate` | Gate for an **unknown/empty** category. Keep at `APPROVE_2PERSON` (never `ALLOW`). |
| `categories` | Map of playbook `category` → base gate. |
| `irreversible_categories` | Categories treated as non-reversible (feeds the risk `reversibility` term). |
| `risk.weights` | Weights for `asset_criticality`, `reversibility`, `low_confidence`. |
| `risk.escalate_thresholds` | `to_1click` / `to_2person` cutoffs on the `0..1` risk score. |
| `always_2person_targets` | `asset_tags` / `identity_tags` that force `APPROVE_2PERSON` (Phase 4). |

**Shipped category map (excerpt):**

| Category | Gate |
|----------|------|
| `Enrichment`, `Dynamic Analysis`, `Attribute Lookup`, `Message Restoration`, `File Restore` | `ALLOW` |
| `Message Eviction`, `Search and Purge`, `Enable Account`, `File Collection`, `Network Restore` | `APPROVE_1CLICK` |
| `Containment`, `Isolation`, `Process Termination`, `Disable Account`, `DNS Denylisting`, `Executable Denylisting`, `File Eviction`, `Response` | `APPROVE_2PERSON` |
| *(anything not listed)* | `default_gate` = `APPROVE_2PERSON` (fail-safe) |

To add a category, add a `"<Category>": "<GATE>"` entry — no redeploy of code needed,
just ship the updated `policy_config.json`.

---

## 7. Fail-safe guarantees

The guard is designed so **every failure mode holds or blocks — never auto-runs**:

| Situation | Result |
|-----------|--------|
| Unknown / empty category | `default_gate` (`APPROVE_2PERSON`) — held |
| `policy_config.json` missing/corrupt | `PolicyLayer` load → `DENY` defaults |
| Policy layer import/instantiation error | `DENY` (blocked) with a clear message |
| Gated run, but caller has no scoped-token identity | Held (no accountable approver) |
| Invalid/expired `approval_token` | Held; restart the approval |
| Risk inputs absent | Risk gate = `ALLOW` (no *relaxation*; base gate still applies) |

Risk and override can only **raise** the gate; nothing in the pipeline can turn a
held/denied action into an autonomous one.

---

## 8. Audit

Every decision is logged (including `ALLOW`) via the app logger to `phantom.log`,
which is forwarded to Splunk:

```
[soar_mcp.policy] decision={"gate":"APPROVE_2PERSON","reason":"base=APPROVE_2PERSON risk=0.00->ALLOW override=ALLOW => APPROVE_2PERSON","risk_score":0.0,...}
[soar_mcp.policy] approval status=pending have=1 need=2 approver=alice pid=571
```

Splunk search:
```spl
index=* "[soar_mcp.policy]" | table _time, host, _raw
```

---

## 9. End-to-end test (verified live)

1. Create/pick a playbook with **Category = `Containment`** (e.g. an empty Start→End
   playbook is zero-risk).
2. Enable the policy layer (§5) and reconnect the MCP client.
3. Ask the client: *"Run playbook `Claude_policy_test` on container 127."*
4. **Expected — held, not run:**
   ```
   ⏸ Approval required by policy — 2 distinct approver(s).
     Playbook: Claude_policy_test | Category: Containment | Gate: APPROVE_2PERSON
     This SOAR MCP token is not a scoped token, so no accountable approver identity
     is available. Mint a scoped MCP token per approver ('mint mcp token' action) and
     retry; execution stays held until then.
   ```
5. **Contrast:** set the category to `Enrichment` → the same call **runs** (`ALLOW`).

---

## 10. Roadmap / known gaps

- **Phase 4 (#139)** — asset/identity context enrichment: source `asset_criticality`
  and the target tags from case artifacts (config-driven tag map) so risk-escalation
  and the target override become active in the live path.
- **Diagnostics** — `diagnose_soar_mcp_environment` does not yet report `policy_enabled`
  in the security posture (planned).

---

## 11. Related issues / source

- Epic **#135**; phases **#136** (core), **#137** (guard), **#138** (approvals).
- UI checkbox **#144** · run-by-name **#148**.
- Source: [`policy/policy_layer.py`](../policy/policy_layer.py),
  [`policy/approvals.py`](../policy/approvals.py),
  [`policy/policy_config.json`](../policy/policy_config.json),
  guard wiring in [`soar_mcp_tools.py`](../soar_mcp_tools.py) (`_policy_gate`, `call_tool`).
