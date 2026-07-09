## Reading sqlite3 db file
- controlplane module converts policy.json to policy.db and place inside `/var/ztfp/policies/tenant-id/`
- Now dataplane(fast path) will read this file and create a AST.

### Components

| Type | Role |
|------|------|
| `struct TenantPolicy` | Per-tenant in-memory policy. Per tenant struct, this is created after reading policy.db, filling entries in TenantPolicy struct |
| `PolicyAST` | Indexed structures inside `TenantPolicy` (domain maps, trie, method index, regex bucket) built after DB read |
| `TenantPolicyRegistry` | `tenant_id` → `*TenantPolicy`; LRU eviction; bounded cold-load workers; fsnotify hook |
| `LoadFromDB(path)` | Open SQLite read-only → read rows → construct `TenantPolicy` → build AST → return (closes DB) |
| `Decide(domain, method)` | Method on `TenantPolicy`; first-match walk over AST under read lock |

### Code
`TenantPolicyRegistry.Watch()` the watcher keeps ztfp in sync with disk when a tenant’s `policy.db` changes — without restarting the process.
```go
proxy/cmd/main.go
    cfg, err := config.Load("config.yaml")  // Read yaml file

    policyRegistry := policy.NewRegistry(policy.RegistryConfig{     //Create policy registry
		PolicyDir:             cfg.PolicyDir,   //"/var/ztfp/policies/"
		CacheSize:             cfg.PolicyCacheSize, //yaml:policy_cache_size
		LoadWorkers:           cfg.PolicyLoadWorkers,   //yaml:policy_load_workers
		LoadTimeout:           cfg.PolicyLoadTimeout,   //yaml:policy_load_timeout
		DefaultDenyOnLoadFail: true,
	}, logger)

    policyRegistry.Watch(watchCtx);     // Add Watcher to policy Dir(with rebound)
```

### How `LoadFromDB()` works

`LoadFromDB` is a **pure load function**: given a path such as `/var/ztfp/policies/42/policy.db`, it returns a ready-to-use `*TenantPolicy` or an error. It runs on a **background worker** (cold-load pool or fsnotify reload), never on the HTTP hot path.

```
policy.db (disk, read-only)
    │
    ▼  LoadFromDB(path)
TenantPolicy {
    tenant_id, default_action, evaluation_order
    rules []RuleRecord          ← deserialized from SQL rows
    ast  *PolicyAST             ← buildAST(rules)
    mu   sync.RWMutex
}
    │
    ▼  Decide(domain, method)   ← read lock, walk ast only
terminal action (+ inspect flags)
```

### Startup when no tenants exist yet

ztfp **does not** call `LoadFromDB` for every possible tenant at process start. On boot:

1. **`TenantPolicyRegistry` starts empty** — no `TenantPolicy` values in the LRU; RAM use for policy is near zero.
2. **Policy directory is ensured** — create `/var/ztfp/policies/` if missing (from `ZTFP_POLICY_DIR`). An empty directory is valid.
3. **fsnotify watcher starts** — watches the policy root for creates, writes, and renames under `{tenant_id}/policy.db`.
4. **Proxy accepts traffic** — HTTP/CONNECT on `:8080` as today. Policy loading is **lazy** unless a tenant is pre-warmed (optional operator choice).

If `/var/ztfp/policies/` has **no tenant subdirectories** or no `policy.db` files yet, nothing is loaded and nothing fails at startup. The process is healthy; it simply has no cached tenant policies.

When a request arrives with JWT `tenant_id = 1`:

- **Strict tenancy** (`ZTFP_TENANT_MODE=strict`): if `/var/ztfp/policies/1/policy.db` does not exist, deny **403** before policy evaluation — same as today’s “unknown tenant” path.
- **Cache miss but file exists**: enqueue cold load → worker runs `LoadFromDB` → `TenantPolicy` enters LRU → `Decide()` runs.
- **Cache miss and load fails** (corrupt DB): log + metric; deny or fall back per config; do not crash the process.

There is no requirement to restart ztfp after the first `policy.db` appears on disk.

### When a `policy.db` appears later

Policy lands on disk in two common ways: control-plane upload (`POST …/policy`) or manual copy after `python -m policy_compiler.cli`. In both cases the sequence is:

1. File appears at `/var/ztfp/policies/{tenant_id}/policy.db`
2. **fsnotify** reports CREATE or WRITE on that path
3. **Debounce** — the watcher waits a short quiet period (typically **250–500 ms**) before scheduling **one** reload for that tenant.
**Debounce** means: do not act on the first filesystem ping immediately; start a timer, and **reset the timer** every time another event arrives for the same tenant directory. When the timer finally expires with no new events, run a single reload. Without debouncing, ztfp could call `LoadFromDB` three times in 100 ms for one logical policy change. Debouncing collapses that burst into **one job**.