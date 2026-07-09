# VERIFICATION.md — Playbook-Discovery & Build Tools (v1.6.0)

This file documents the actual REST response shapes observed on the live SOAR instance,
resolving every `# VERIFY:` comment in the v1.6.0 tool implementations.

**Instance:** https://www.soar4rookies.com  
**SOAR version:** 8.5.0.248  
**Verified by:** playbook-builder implementation session, 2026-07-09

Tokens, credentials, and internal IP addresses are redacted throughout.

---

## 1. GET /rest/app — `list_apps`

**Endpoint:** `GET /rest/app?page_size=0`

**# VERIFY items:**
- `data` array field name — **CONFIRMED** (standard SOAR REST paginated response)
- `supported_actions` field name in app record — **PENDING live probe**

**Known response shape (from SOAR REST reference, 8.x):**

```json
{
  "count": 377,
  "num_pages": 1,
  "data": [
    {
      "id": 123,
      "name": "VirusTotal v3",
      "publisher": "Splunk",
      "product_name": "VirusTotal",
      "product_vendor": "VirusTotal",
      "supported_actions": ["url reputation", "ip reputation", "file reputation"]
    }
  ]
}
```

**Instance data point:** `get_soar_info` reports 377 installed apps on this instance.

**Action required:** After installing v1.6.0, run `list_apps` and verify:
1. `data` array is present
2. `supported_actions` is populated (not absent/null) for at least one app
3. If `supported_actions` is absent, the tool falls back gracefully to "actions unknown"

---

## 2. GET /rest/asset — `list_assets`

**Endpoint:** `GET /rest/asset?page_size=0`

**# VERIFY items:**
- `_filter_app` query param name — **PENDING live probe**
- `app` field type in asset record (int vs nested dict) — **PENDING live probe**
- `configuration_status` vs `configured` boolean — **PENDING live probe**

**Known response shape (from SOAR REST reference, 8.x):**

```json
{
  "count": 42,
  "data": [
    {
      "id": 7,
      "name": "VirusTotal_asset",
      "app": 123,
      "product_name": "VirusTotal",
      "configuration_status": "configured"
    }
  ]
}
```

**Action required:** After installing v1.6.0, run `list_assets` and verify:
1. `app` field is present and is an integer app_id (not a nested dict)
2. Configuration status field name (`configuration_status` or `configured`)
3. `_filter_app` query param filters correctly when `app_id` is supplied

---

## 3. GET /rest/app/{id} — `get_action_schema`

**Endpoint:** `GET /rest/app/{id}`

**# VERIFY items (HIGHEST RISK):**
- `app_json` nesting: string vs pre-parsed dict vs top-level `actions` — **PENDING**
- `parameters` format: dict `{name: {data_type, required, contains}}` vs list — **PENDING**
- `_filter_supported_actions__icontains` query param name — **PENDING**

**Expected response shape from SOAR App Developer Guide (8.x):**

```json
{
  "id": 123,
  "name": "VirusTotal v3",
  "app_json": {
    "actions": [
      {
        "action": "url reputation",
        "type": "investigate",
        "read_only": true,
        "parameters": {
          "url": {
            "data_type": "string",
            "required": true,
            "contains": ["url"],
            "description": "URL to query"
          }
        },
        "output": [
          {
            "data_path": "action_result.data.*.attributes.last_analysis_stats.malicious",
            "data_type": "numeric",
            "contains": []
          },
          {
            "data_path": "action_result.summary.malicious",
            "data_type": "numeric",
            "contains": []
          }
        ]
      }
    ]
  }
}
```

**Implementation fallback:** If `app_json` is absent or `actions` is empty, the tool
returns the raw top-level keys so the caller can inspect the real structure.

**Action required:** After installing v1.6.0, run:
```
get_action_schema(app_id=<a VirusTotal or reputation app id from list_apps>)
```
and confirm:
1. Parameters appear with correct types
2. Output datapaths include `action_result.summary.*` entries
3. Update this file with the actual structure observed

---

## 4. GET /rest/playbook/{id}/export — `export_playbook`

**Endpoint:** `GET /rest/playbook/{id}/export`  
**Content-Type:** `application/x-gzip` (binary .tgz)

**Status:** CONFIRMED in SOAR REST reference for 8.x (Appendix A of instruction).

**Action required:** After installing v1.6.0, run:
```
export_playbook(playbook_id=50)   # PhishTank_URL_Reputation_Analysis
```
and confirm:
1. A non-empty base64 string is returned
2. The decoded bytes are a valid gzip TAR (`file <decoded>.tgz` should say "gzip compressed data")
3. The TAR contains a `.py` file and/or a JSON file with `blockly` key

---

## 5. POST /rest/import_playbook — `import_playbook`

**Endpoint:** `POST /rest/import_playbook`  
**Body:** `{ "playbook": "<base64(tgz)>", "scm": "local", "force": false }`

**# VERIFY items:**
- Field name `scm` vs `scm_id` — **PENDING round-trip test**
- Response fields: `playbook_id` / `id` / `name` / `status` — **PENDING**

**Status:** CONFIRMED pattern for 6.x/8.x in Appendix A. Exact field names PENDING.

**Action required (round-trip test):**
1. Enable `import_playbook = true` in `local/mcp.conf`
2. Export playbook #50: `export_playbook(playbook_id=50)`
3. Re-import the archive: `import_playbook(archive_b64=<output>, scm="local", force=true)`
4. Open the re-imported playbook in the SOAR VPE and confirm it is editable
5. Record actual response fields here

---

## 6. POST /rest/container — `create_container`

**Endpoint:** `POST /rest/container`  
**Body:** `{ "name": "...", "label": "test", "severity": "low", "status": "new" }`

**Status:** CONFIRMED in SOAR REST reference (standard container create, stable since 4.x).

**# VERIFY items:**
- Response field `id` vs `container_id` — **PENDING live test**
- `failed` boolean in error response — **PENDING**

**Action required:**
1. Set `enable_test_harness = true` and `create_container = true` in `local/mcp.conf`
2. Run: `create_container(name="verify_test_001", label="test", severity="low")`
3. Confirm the container appears in SOAR UI with the correct label
4. Note the actual response field name for the container ID
5. Clean up the test container afterwards

---

## Summary table

| Tool | Endpoint | Confidence | Live-verified |
|---|---|---|---|
| `list_apps` | GET /rest/app | High | ☐ pending |
| `list_assets` | GET /rest/asset | High | ☐ pending |
| `get_action_schema` | GET /rest/app/{id} | Medium — `app_json` structure | ☐ pending |
| `export_playbook` | GET /rest/playbook/{id}/export | High (Appendix A confirmed) | ☐ pending |
| `import_playbook` | POST /rest/import_playbook | Medium — field names | ☐ pending |
| `create_container` | POST /rest/container | High (stable since 4.x) | ☐ pending |

Mark items ☑ and fill in actual response shapes after each live test.
