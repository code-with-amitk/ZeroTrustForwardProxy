- [Present Design : full document upload](#pd)
  - [Control plane](#cp1)
  - [Data plane](#dp1)
    - [What's in /var/ztfp/tenant_id/ path](#path)
      - [policy.meta.json](#meta)
- [Future Design](#fd)
  - [1. Incremental AST](#o1)

# Delta Policy Change
A tenant may have hundreds or thousands of rules but change only one rule at a time — for example, add LinkedIn to a social-media block list or tighten DLP on one domain. Sending the entire `policy.json` on every save wastes bandwidth and forces the control plane to re-validate and re-compile every rule even when only one row changed.

<a href=pd></a>

## Present Design: full document upload
Every policy save uses **one HTTP POST** with the **complete** policy envelope:

```http
POST /api/v1/tenants/1/policy
Authorization: Bearer <token>
Content-Type: application/json

{ entire policy.json — all blocks, all rules }
```

<a href=cp1></a>

### Control plane
- Implementation: `controlplane/api/server.py` → `store_policy()` → validate → compile → write artifacts.
- Validates whole document, Recompiles entire policy.db, Writes policy.json.
- Control plane work: **O(R)** — validate all R rules, rewrite entire `policy.db`, bump `version` in `policy.meta.json`.

<a href=dp1></a>

### Data Plane(Go)
Data plane work on reload: **O(R)** — `LoadFromDB` + `buildAST` for all R rules
```
policy.db changed (upload or copy)
  → fsnotify (1 watcher goroutine)
  → debounce 300ms per tenant
  → ReloadTenant(tenantID)
       → LoadFromDB (read all rows)
       → buildAST (all 500 rules)
       → TenantPolicy.Swap() on cached entry
```

<a href=path></a>
#### What's in /var/ztfp/tenant_id/ path
| File | Purpose |
|------|---------|
| `policy.json` | Canonical source on disk (audit, rollback, human read) |
| `policy.db` | Compiled SQLite — **only file the Go data plane reads** |
| `policy.meta.json` | `version`, `checksum`, `rule_count`, `compiled_at` |


<a href=meta></a>
##### [policy.meta.json](../../controlplane/test_policies/policy.meta.json)
```json
{
  "tenant_id": 1,
  "version": 3,                       <<<<<<<<< This will be bumped
  "rule_count": 3,
  "checksum": "7dcb94d00d03290acd007cc917c113a20d8f7d5c6f360423109ef7773557a73a",
  "compiled_at": "2026-07-09T10:58:47Z",
  "schema_version": "2",
  "evaluation_order": ["bypass", "egress_ip", "enterprise_browser", "rtp"],
  "source_json": "/home/amit/ZeroTrustForwardProxy/controlplane/test_policies/policy.json",
 
}
```
|Feild|Description|
|---|---|
|version|starts at `1` on first upload, then increments by 1 on each POST. The POST response returns the same `version` so the UI can store it for the next PATCH.|
|checksum|SHA-256 hash of `policy.json` bytes after validation|
|schema_version|JSON schema + SQLite layout|

**Checksum usage**

| Use | Role |
|-----|------|
| **Integrity** | Proves `policy.json` on disk matches what was last compiled |
| **Change detection** | Any edit to the merged document changes the checksum |
| **Not for locking** | Two different policy states could theoretically collide (extremely unlikely); **`version`** is used for PATCH conflicts, not `checksum` |


<a href=fd></a>

## Future Design

- Let admin added "linkedin" to block list.
- Tenant UI sends delta policy.json, 

**Earlier** policy.json (Does not had linkedin)
```http
{
  "tenant_id": 1,
  "default_action": "ALLOW",
  "policies": {
    "rtp": {
      "rules": [
        {
          "id": "rtp-block-social",
          "name": "Block social media",
          "priority": 10,
          "conditions": {
            "domains": ["(facebook|instagram|twitter|tiktok)\\.com$"],
            "methods": ["GET", "POST"],
            "saml_groups": ["all-employees"]
          },
          "action": "BLOCK",
          "message": "Social media blocked by RTP policy"
        },
        ... other rules ...
      ]
    }
  }
}
```

**Delta Update** policy.json(have linkedin)
```http
PATCH /api/v1/tenants/{tenant_id}/policy
Authorization: Bearer <token>
Content-Type: application/json

{
  "base_version": 3,    <<<<<<<It is the client telling the server: “I believe the current policy is revision=3(policy.meta.json).The server compares that to the **`version`** integer in `policy.meta.json`

  "ops": [              <<<<<<<<<<< Ordered list of changes to apply
    {
      "op": "upsert",         <<<<<<<<< Operation(upsert). (add or replace rule by `id`) or `delete`
      "policy_type": "rtp",   <<<<<<< `rtp`, `bypass`, `egress_ip`, `enterprise_browser`
      "rule": {                   <<<<<<< Full rule object for `upsert` (same shape as in POST body)
        "id": "rtp-block-social",
        "name": "Block social media",
        "priority": 10,
        "conditions": {
          "domains": ["(facebook|instagram|twitter|tiktok|linkedin)\\.com$"],
          "methods": ["GET", "POST"],
          "saml_groups": ["all-employees"]
        },
        "action": "BLOCK",
        "message": "Social media blocked by RTP policy"
      }
    }
  ]
}
```
- Client last saw version: 3  →  PATCH { "base_version": 3, "ops": [...] }
- Server reads policy.meta.json → version is 3  →  apply ops, write version: 4

