## Standalone Scaling — Policy + HTTP (No Kubernetes)

- This section covers a **single standalone VM** (e.g. one AWS EC2 instance) or one bare-metal host. 
- Phase 2 adds multi-VM scaling via Kubernetes.

### Policy memory: LRU

- All 10,000 tenant policies(ie sqlite.db files) are stored on **disk (/var/ztfp/tenants/tenant-id/policy.db)** (~10–50 GB total).
- RAM holds only a **bounded LRU cache** of tenant engines (tunable, e.g. 500–2,000 entries).

| Cached tenants | Rules each | Est. RAM |
|----------------|------------|----------|
| 500 | 5,000 | ~2.5–7 GB |
| 2,000 | 5,000 | ~10–28 GB |
| 10,000 (worst case, all hot) | 5,000 | ~50–150 GB |

On a single VM, **10,000 simultaneously active tenants** is the hard worst case: the LRU churns constantly or grows until memory is exhausted.

### Single-VM strategy for 10,000 active tenants

If all 10,000 tenants remain active and each needs low-latency policy, a single VM cannot hold 50M(10000 tenants x 500 rules each) rules in optimized form. Escalation path on one machine:

| Mechanism | Purpose |
|-----------|---------|
| **LRU cap** (`ZTFP_POLICY_CACHE_SIZE`) | Hard limit on tenant engines in RAM; evict cold tenants back to disk-only |
| **[goroutine pool](#grp)** | 4–8 goroutines building AST from SQLite; excess cache misses queue instead of spawning unbounded loaders |
| **Two-tier policy store** | Hot tenants: full AST in LRU; warm tenants: mmap/read-only SQLite without full AST (slower `Decide`, lower RAM); cold: load on demand |
| **[External PDP](./External_PDP.md) (future A3)** | Offload `(tenant_id, domain, method)` to a dedicated policy service when single-VM RAM ceiling is hit |
| **Tenant tiers** | Enterprise tenants pinned in cache; free-tier tenants evicted first under memory pressure |
| **Decide() isolation** | Read lock only; microsecond-scale — HTTP forwarding is not blocked by policy evaluation itself |

Policy **compile** (Python) and **reload** (fsnotify) run off the request path with debouncing. Upload storms from many tenants update disk; ztfp swaps engines in background.

<a href=grp></a>
#### goroutine pool
- At startup, ztfp creates a small channel-backed worker queue(typically 4–8 goroutines). This number is controlled by ZTFP_POLICY_LOAD_WORKERS.
- How number of go routines(=threads) decide?
-- its decided on number of cores(vcpu's) system have. For 8core(4 goroutines)
-- its not decided on number of hot tenants, if tenants reach 10k or 20k and we are deciding on number, it will blow up the memory.

- Each go-routine(worker) job is **cold load** ie open `/var/ztfp/policies/{tenant_id}/policy.db` as read-only, create *PolicyRule structure for particular tenant, then add to AST Tree map everyting in RAM
```
struct PolicyRule{..}

AST (map)
    key=tenantid    value(*PolicyRule)
    1               {...}
    2               {...}
```

### When single-VM policy RAM is insufficient

If all 10,000 tenants remain active and each needs low-latency policy, a single VM cannot hold 50M rules in optimized form. Escalation path on one machine:

1. Increase VM RAM and LRU size (vertical scale).
2. Enable **warm tier** (SQLite-only evaluation without full AST — higher CPU, lower RAM).
3. Deploy **external PDP** on a second VM; ztfp becomes forward-only for policy decisions.
4. **Phase 2 — Kubernetes pod scaling** (see end of document).

<a href=endtoend></a>
### End-to-end for one request
- Request arrives with `tenant_id = 42`. If `42` is in the LRU, a request goroutine takes a **read lock** on tenant 42’s `struct *PolicyEngine` in LRU, runs `Decide()`, releases the lock — microseconds, no SQLite.
- If `42` is not cached, the request goroutine enqueues a load job; one of the 4–8 loader workers reads `42/policy.db`, builds the AST into a new `struct *PolicyEngine`, inserts it into the LRU, signals done; then the request runs `Decide()`. After that, tenant 42 stays hot until LRU eviction or policy reload replaces the engine.