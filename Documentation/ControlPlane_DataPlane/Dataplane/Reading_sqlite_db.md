## Reading sqlite3 db file
- controlplane module converts policy.json to policy.db and place inside `/var/ztfp/policies/tenant-id/`
- Now dataplane(fast path) will read this file and create a AST.

### Code
#### fsnotify
Watcher read `policy.db` changes — without restarting the process.
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

#### `LoadFromDB()`

- Policy path given: `/var/ztfp/policies/42/policy.db`
- return `*TenantPolicy` or an error.
- Runs as background worker, not on hot path

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

#### Startup when no tenants exist yet

ztfp **does not** call `LoadFromDB` for every possible tenant at process start. On boot:

1. Empty `TenantPolicy`.
2. created empty `/var/ztfp/policies/`
3. fsnotify watches for creates, writes, and renames under `{tenant_id}/policy.db`.

- **Strict tenancy** (`ZTFP_TENANT_MODE=strict`): if `/var/ztfp/policies/1/policy.db` does not exist, deny **403** to every request
- **Cache miss and load fails** (corrupt DB): log + metric; deny or fall back per config; do not crash the process.

#### When a `policy.db` appears later

Policy lands on disk by control-plane upload (`POST …/policy`)

1. File appears at `/var/ztfp/policies/{tenant_id}/policy.db`
2. **fsnotify** reports CREATE or WRITE on that path
3. **Debounce** — the watcher waits a short quiet period (typically **250–500 ms**) before scheduling **one** reload for that tenant.
**Debounce** means: do not act on the first filesystem ping immediately; start a timer, and **reset the timer** every time another event arrives for the same tenant directory. When the timer finally expires with no new events, run a single reload. Without debouncing, ztfp could call `LoadFromDB` three times in 100 ms for one logical policy change. Debouncing collapses that burst into **one job**.