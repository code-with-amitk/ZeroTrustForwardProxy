- [AST](#ast)
- [Runtime flow](#rt)

<a href=ast></a>
## AST
- We store [TenantPolicyRegistry](policy/registry.go) which stores `tenant_id → *TenantPolicy` (which holds the AST pointer). 

```bash
    map [key=tenantIDInt64] value=*TenantPolicy
```

<a href=rt></a>
## Runtime flow
```
HTTP packet arrives (:8080)
        │
        ▼
proxy.evaluate()
        │
        ├─① auth.ExtractAuthorizationnHeader(r)
        │     Read Bearer JWT
        │     jwt.ValidateJWT → claims.TenantID (int64)
        │     strict mode: reject if /var/ztfp/policies/{id}/policy.db missing
        │     dev mode: tenant_id=0 → default_tenant_id (e.g. 1)
        │
        │     Result: tenantID = 1, user = "alice"
        │
        ├─② domain = r.Host / URL host   (e.g. "www.facebook.com")
        │     method = r.Method          (e.g. "GET")
        │
        └─③ s.Policy.Decide(tenantID, domain, method)
              │
              ▼
        TenantPolicyRegistry.Decide(1, "www.facebook.com", "GET")
              │
              ▼
        TenantPolicyFor(1)   ← lookup tenant_id → *TenantPolicy
              │
              ├─ HIT:  cache[1] → *TenantPolicy → tp.Decide(...)
              │
              └─ MISS: load /var/ztfp/policies/1/policy.db
                       LoadFromDB → buildAST → insert cache[1] → Decide(...)
```