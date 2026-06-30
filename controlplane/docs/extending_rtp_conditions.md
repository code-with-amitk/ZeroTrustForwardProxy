# Extending RTP policy conditions

This guide explains how to add a new match field to **Real-time Protection (RTP)** rules — for example `"saml_groups": ["group1", "group2"]` — and how to verify the change with tests.

RTP conditions are stored as JSON in SQLite (`conditions_json`). The control plane validates known fields at upload time; the Go data plane (Phase 1C) will read them at enforcement time.

## Example: `saml_groups`

`saml_groups` is already defined in the JSON Schema under `rtp_conditions`. An RTP rule can include:

```json
{
  "id": "rtp-saml",
  "conditions": {
    "domains": [".*\\.internal\\.example\\.com$"],
    "saml_groups": ["engineering", "finance"]
  },
  "inspect": { "dlp": true },
  "action": "ALLOW",
  "scan_fallback": "fallback_block"
}
```

See `testdata/tenant_policy_sample.json` for a full multi-block tenant document.

## Steps to add a new RTP condition field

Use these steps when introducing a field such as `department`, `device_posture`, or another SAML-derived attribute.

### 1. Update JSON Schema

Edit `controlplane/schema/policy.schema.json` → `$defs/rtp_conditions/properties`:

```json
"department": {
  "type": "array",
  "items": { "type": "string" }
}
```

`rtp_conditions` uses `"additionalProperties": true`, so unknown keys are accepted at compile time even before schema updates — but adding explicit properties documents the field and enables type checking.

### 2. Add business validation (optional)

If the field contains regex patterns or has cross-field rules, extend `_validate_rule_business()` in `controlplane/policy_compiler/validator.py`.

For simple string lists (like `saml_groups`), schema validation is usually enough.

### 3. Compiler changes

No compiler change is required for match-only fields. `compiler.py` serializes the entire `conditions` object into `conditions_json`:

```python
json.dumps(conditions)
```

The Go data plane will deserialize `conditions_json` when Phase 1C implements RTP matching.

### 4. Add or update tests

**Run existing tests:**

```bash
cd controlplane
source .venv/bin/activate   # if not already active
pytest tests/ -v
```

**Add a focused test** in `controlplane/tests/test_integration.py`:

```python
def test_rtp_saml_groups_persisted_in_sqlite(tmp_path):
    doc = json.loads(json.dumps(MULTI_BLOCK_POLICY))
    doc["policies"]["rtp"]["rules"][1]["conditions"]["saml_groups"] = ["group1", "group2"]
    stored = store_policy(tmp_path, 1, doc)
    conn = sqlite3.connect(stored.db_path)
    try:
        row = conn.execute(
            "SELECT conditions_json FROM rules WHERE policy_type='rtp' AND id='2'"
        ).fetchone()
        conditions = json.loads(row[0])
        assert conditions["saml_groups"] == ["group1", "group2"]
    finally:
        conn.close()
```

**Validate upload via API** (optional manual check):

```bash
export ZTFP_POLICY_DIR=/tmp/ztfp-policies
export CONTROL_PLANE_API_TOKEN=dev
python -m api.server &
curl -X POST http://127.0.0.1:8090/api/v1/tenants/1/policy \
  -H "Authorization: Bearer dev" \
  -H "Content-Type: application/json" \
  -d @../testdata/tenant_policy_sample.json
sqlite3 /tmp/ztfp-policies/1/policy.db \
  "SELECT conditions_json FROM rules WHERE policy_type='rtp' AND id='2';"
```

### 5. Update sample fixture

Add the new field to `testdata/tenant_policy_sample.json` so curl examples and integration tests stay representative.

### 6. Data plane (Phase 1C — later)

When implementing Go enforcement:

1. Extend the AST / matcher to read the new key from deserialized conditions.
2. Join JWT/SAML identity claims with rule conditions before `Decide()`.
3. Add Go unit tests mirroring the Python SQLite persistence test.

## Policy evaluation order (reference)

The control plane stores this order in `policy_meta.evaluation_order` and `policy.meta.json`:

1. **bypass** — SSL DND vs decrypt (CONNECT)
2. **egress_ip** — outbound gateway source IP
3. **enterprise_browser** — managed browser / RBI
4. **rtp** — DLP/MCP inspect → terminal action or scan fallback

Within each block, rules are ordered by `priority` (lower number first).

## Legacy migration

Flat documents with top-level `rules[]` and actions `inspect_dlp` / `inspect_mcp` are normalized automatically:

| Legacy | Canonical RTP |
|--------|-----------------|
| `"action": "inspect_dlp"` | `"inspect": { "dlp": true }`, `"action": "ALLOW"`, `"scan_fallback": "fallback_block"` |
| `"action": "inspect_mcp"` + `mcp` object | `"inspect": { "mcp": { ... } }`, `"action": "ALLOW"`, `"scan_fallback": "fallback_block"` |
| `"action": "block"` | `"action": "BLOCK"` in `policies.rtp.rules` |

Normalization runs in `policy_compiler/normalizer.py` before schema validation.
