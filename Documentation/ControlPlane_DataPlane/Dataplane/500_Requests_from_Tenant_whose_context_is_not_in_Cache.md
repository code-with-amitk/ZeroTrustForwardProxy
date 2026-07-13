- [Problem](#problem)
- [Cache stampede](#stampede)
- [How ztfp handles it (design + code)](#ztfp)
- [500 requests, one cold tenant — step by step](#walkthrough)
- [Configuration knobs](#config)
- [How Netskope handles a similar situation](#netskope)
- [Comparison](#comparison)
- [Failure modes and tuning](#failure)
- [Related reading](#related)

# 500 Requests from Tenant whose context is not in Cache

<a name="problem"></a>
## Problem

**Situation:** `tenant_id = 42` is known (from JWT or tunnel context), but tenant `42` is **not** in the in-memory LRU cache — for example first traffic after deploy, after LRU eviction, or immediately after a new `policy.db` landed on disk.

**Burst:** **500 concurrent HTTP requests** arrive for tenant `42` at the same time.

**Risk (cache stampede):** Without coordination, all 500 request goroutines could each:

1. Open `/var/ztfp/policies/42/policy.db`
2. Read every rule row from SQLite
3. Compile regexes and build the full AST
4. Insert into cache

That duplicates expensive work **500×**, spikes CPU, exhausts file descriptors, and can OOM the proxy — while user requests stall.

**Goal:** Exactly **one** cold load for tenant `42`; the other **499** wait and then reuse the same `*TenantPolicy`.

---

<a name="stampede"></a>
## Cache stampede

A **cache stampede** (or **thundering herd**) happens when many concurrent callers miss the same cache key and all try to populate it at once.

```
Without protection (bad):

  Request 1 ──► LoadFromDB(42) ──► build AST ──► insert
  Request 2 ──► LoadFromDB(42) ──► build AST ──► insert   } 500× duplicate
  ...
  Request 500 ► LoadFromDB(42) ──► build AST ──► insert
```

For one tenant with 5,000 rules, a single cold load might take **100–500 ms** on NVMe. Five hundred parallel loads could saturate the host for **tens of seconds**.

---

<a name="ztfp"></a>
## How ztfp handles it (design + code)

ztfp uses **three layers** on a cache miss for a given `tenant_id`:

| Layer | Mechanism | What it prevents |
|-------|-----------|------------------|
| **1. Request coalescing** | `golang.org/x/sync/singleflight.Group` | 500 goroutines → **1** load orchestrator per `tenant_id` |
| **2. Bounded loader pool** | Fixed **worker goroutines** + channel queue | At most **N** concurrent `LoadFromDB` + AST builds cluster-wide |
| **3. LRU cap** | Evict least-recently-used tenants when full | Unbounded RAM growth from too many hot tenants |

Implementation: `policy/registry.go` — `TenantPolicyRegistry`.

### Layer 1 — Singleflight (same tenant, 500 requests)

```go
// Only one goroutine runs the inner load for tenant_id "42".
// The other 499 block on group.Do until that call returns.
v, err, _ := r.group.Do(fmt.Sprintf("%d", tenantID), func() (interface{}, error) {
    // ... enqueue one load job, wait for worker result ...
})
```

- **Key:** string form of `tenant_id` (e.g. `"42"`).
- **Effect:** All 500 requests share **one** `Do` callback execution path for tenant `42`.
- **After success:** All waiters receive the same `*TenantPolicy` pointer; subsequent requests hit the LRU and skip `loadTenant` entirely.

This is **request coalescing** / **single-flight** deduplication — not 500 separate disk reads for one tenant.

### Layer 2 — Cold-load worker pool (not one thread per request)

At registry startup:

```go
loadCh: make(chan loadJob, cfg.CacheSize)   // buffered queue
for i := 0; i < cfg.LoadWorkers; i++ {
    go r.loadWorker()   // fixed pool — default 4 goroutines
}
```

| Component | Default | Env / YAML |
|-----------|---------|------------|
| **Loader workers** | **4** goroutines | `ZTFP_POLICY_LOAD_WORKERS` / `policy_load_workers` |
| **Load queue depth** | Buffer = **500** slots | Same as `CacheSize` default (channel capacity) |
| **Wait timeout** | **5 s** | `ZTFP_POLICY_LOAD_TIMEOUT` / `policy_load_timeout` |

**Important:** These are **Go worker goroutines**, not one OS thread per request. HTTP handlers are also goroutines (from `net/http`). Under load you may have **thousands of request goroutines**, but only **`LoadWorkers`** (typically 4–8) perform cold `LoadFromDB` at any instant.

**Worker sizing (rule of thumb):**

| vCPUs | Suggested `LoadWorkers` |
|-------|-------------------------|
| 4 | 2–4 |
| 8 | 4 (default) |
| 16+ | 4–8 |

Size from **CPU + disk**, not from tenant count or request rate. More workers help when **many different** tenants cold-miss at once; they do **not** help 500 requests for the **same** tenant (singleflight already collapses that to one load).

Each worker runs:

```
loadFromDisk(tenantID)
  → open policy.db (read-only)
  → hydrate RuleRecord rows
  → buildAST() — compile regexes, index by policy_type
  → insert into LRU
  → signal waiting request goroutine(s)
```

Typical cost: **5–50 ms** (500 rules) to **100–500 ms** (5,000 rules) — paid **once per LRU residency**, not per request.

### Layer 3 — LRU cache size

| Setting | Default | Meaning |
|---------|---------|---------|
| **`ZTFP_POLICY_CACHE_SIZE`** | **500** | Max **tenant policies** (`*TenantPolicy` + full AST) in RAM |

When inserting tenant `N+1` would exceed the cap, the **least recently used** tenant is evicted from the map. Evicted tenants return to **cold** state (only `policy.db` on disk). The next request for that tenant triggers cold load again — again protected by singleflight.

**Memory estimate (order of magnitude):**

| Cached tenants | Rules each | Approx. RAM |
|----------------|------------|-------------|
| 500 (default cap) | 5,000 | ~2.5–7 GB |
| 2,000 | 5,000 | ~10–28 GB |

One `TenantPolicy` includes rules + `ASTMap` + compiled `*regexp.Regexp` — evicting one entry frees the whole tenant footprint.

### Hot path after cache is warm

Once tenant `42` is in the LRU:

```
TenantPolicyFor(42)
  → getCached(42)  HIT
  → tp.Decide(domain, method)
       → tp.mu.RLock()
       → walk ASTMap in memory
       → RUnlock()
```

No SQLite, no AST build, no loader queue — **microseconds** per request.

---

<a name="walkthrough"></a>
## 500 requests, one cold tenant — step by step

**Setup:** Tenant `42` not in cache. `LoadWorkers=4`, `CacheSize=500`, `LoadTimeout=5s`. All requests carry `tenant_id=42`.

```mermaid
sequenceDiagram
    autonumber
    participant R1 as Request goroutines<br/>(×500)
    participant Reg as TenantPolicyRegistry
    participant SF as singleflight.Group<br/>key "42"
    participant Q as loadCh queue
    participant W as loadWorker<br/>(1 of 4)
    participant Disk as policy.db
    participant LRU as LRU cache

    par 500 concurrent Decide(42, ...)
        R1->>Reg: TenantPolicyFor(42)
        Reg->>Reg: getCached(42) → MISS
        R1->>SF: group.Do("42", loadFn)
    end

    Note over SF: Only 1 goroutine runs loadFn;<br/>499 block inside Do

    SF->>SF: getCached(42) → still MISS
    SF->>Q: enqueue loadJob{tenantID:42}
    Q->>W: deliver job
    W->>Disk: LoadFromDB(42/policy.db)
    Disk-->>W: rules + metadata
    W->>W: buildAST()
    W->>LRU: insert(42, TenantPolicy)
    W-->>SF: loadResult OK

    SF-->>R1: *TenantPolicy (all 500 waiters)

    loop Each request
        R1->>Reg: tp.Decide(domain, method)
        Reg->>LRU: RLock + AST walk
        LRU-->>R1: ALLOW / BLOCK
    end

    Note over R1,LRU: Request 501+ → getCached HIT,<br/>no singleflight, no disk
```

### Timeline (typical)

| Time | Event |
|------|--------|
| T+0 ms | 500 requests hit cache miss for tenant `42` |
| T+0 ms | Request #1 enters `singleflight.Do("42")`; #2–#500 block on `Do` |
| T+0 ms | One job enqueued; worker starts `LoadFromDB` |
| T+50–300 ms | Worker finishes AST; LRU insert; job result sent |
| T+50–300 ms | All 500 `Do` waiters wake; each runs `Decide()` (RLock, in-memory) |
| T+later | All further requests for `42` → LRU hit only |

**Latency for the burst:** First wave waits **one cold-load duration** (not 500×). If load takes 200 ms, those 500 requests see ~200 ms policy delay before forward/block — then normal latency.

### Different scenario: 500 cold **different** tenants

If 500 requests are for **500 different** tenant IDs (each missing from cache):

- **Singleflight** dedupes **per tenant** — up to **500 separate** loads still needed over time.
- **Worker pool** caps concurrent loads to **`LoadWorkers`** (e.g. 4).
- Remaining jobs wait in `loadCh` (buffer up to `CacheSize`).

So: **same tenant → 1 load**; **500 tenants → up to 4 loads at a time**, queue for the rest.

---

<a name="config"></a>
## Configuration knobs

| Variable | YAML field | Default | Role |
|----------|------------|---------|------|
| `ZTFP_POLICY_CACHE_SIZE` | `policy_cache_size` | **500** | Max tenants in LRU; load queue buffer size |
| `ZTFP_POLICY_LOAD_WORKERS` | `policy_load_workers` | **4** | Cold-load worker goroutines |
| `ZTFP_POLICY_LOAD_TIMEOUT` | `policy_load_timeout` | **5s** | Max wait for cold load before error |
| `ZTFP_POLICY_DIR` | `policy_dir` | `/var/ztfp/policies` | Root for `{tenant_id}/policy.db` |
| `default_deny_on_load_fail` | (config) | false | If true, block traffic when load fails/timeouts |

**Docker Compose example** (`docker-compose.yml`):

```yaml
ZTFP_POLICY_CACHE_SIZE: "500"
ZTFP_POLICY_LOAD_WORKERS: "4"
```

**Code references:**

| File | Responsibility |
|------|----------------|
| `policy/registry.go` | LRU, singleflight, worker pool, `TenantPolicyFor` |
| `policy/load_db.go` | `LoadFromDB` — SQLite → `TenantPolicy` |
| `policy/ast.go` | `buildAST()` |
| `policy/tenant_decide.go` | `Decide()` under `RWMutex` |
| `config/config.go` | Defaults and env parsing |

---

<a name="netskope"></a>
## How Netskope handles a similar situation

Netskope’s data plane (NewEdge POP / nsproxy) is **multi-tenant at scale** but uses a **different preload model** than “first HTTP request opens SQLite.” Public architecture docs emphasize:

| Aspect | Netskope-style behavior |
|--------|-------------------------|
| **Policy distribution** | Management plane **pushes** compiled policy to POPs on a schedule (often cited ~**15 minutes**) and on admin change — POP holds tenant policy **before** user traffic spikes |
| **Per-tenant isolation** | Each customer tenant has isolated policy partition on the POP; evaluation never mixes tenants |
| **Memory model** | In-memory **real-time policy engine** at the POP — hot policy structures in RAM, not per-request compile from disk |
| **Scale-out** | **Horizontal** — many POP nodes; traffic spread by GSLB / nearest POP; no single VM holds all tenants |
| **Client path** | Netskope Client connects to tenant-scoped gateway; identity in tunnel metadata — policy context tied to tenant at connection time |
| **Stampede avoidance (conceptual)** | Policy **preloaded/replicated** to edge; first request rarely triggers full cold compile on the hot path; edge nodes sized for concurrent tenants in that POP footprint |

Netskope does **not** publish internal details equivalent to “4 loader threads” or “LRU size 500.” Operationally:

- **Enterprise tenants** on a POP are expected to have policy **already resident** after sync from the management plane.
- A sudden **new tenant** or **policy version bump** is absorbed by **background reload** on the POP, not by unbounded parallel reloads from request threads.
- At extreme scale, **more POPs** and **tenant sharding** reduce per-node cold-start pressure.

**Analogy to ztfp:**

| Netskope POP | ztfp |
|--------------|------|
| Policy push + in-memory engine at edge | `policy.db` on disk + LRU + cold load on miss |
| Background policy refresh | fsnotify + debounced `ReloadTenant` |
| Horizontal POP fleet | Single VM today; K8s / external PDP later |
| Implicit dedupe on policy update | `singleflight` + debounced reload |

ztfp’s **singleflight + bounded workers** is the explicit on-box equivalent of “don’t let every request thread rebuild the same tenant context.”

---

<a name="comparison"></a>
## Comparison

| Question | ztfp (implemented) | Netskope (reference) |
|----------|-------------------|----------------------|
| 500 requests, **same** cold tenant | **1** load via singleflight | Policy usually **already in RAM** at POP; update via background sync |
| Max parallel disk loads | **`LoadWorkers`** (default 4) | Not published; background + distributed |
| Cache size | **500** tenants LRU (tunable) | POP memory sized per deployment; tenant policy resident at edge |
| Request waits on miss | Yes, up to **`LoadTimeout`** (5s) | Designed for sub-ms policy eval once resident |
| Reload on policy change | fsnotify debounce ~300 ms | MP → POP push / periodic sync |
| Warm tier (SQLite only, no AST) | Planned, not implemented | Conceptually similar tiering at edge |

---

<a name="failure"></a>
## Failure modes and tuning

### Load timeout

If `LoadFromDB` or AST build exceeds **`LoadTimeout`** (5s), waiters get `ErrPolicyLoadTimeout`.

- **`DefaultDenyOnLoadFail=false` (default):** fail-open — allow with error logged (dev-friendly).
- **`DefaultDenyOnLoadFail=true`:** block traffic until policy loads successfully.

### Queue saturation

If `loadCh` is full, registry spawns a helper goroutine to enqueue the job (`default` branch in `loadTenant`). Jobs still serialize through workers; singleflight prevents duplicate jobs for the **same** tenant.

### Tuning for cold-start bursts

| Symptom | Action |
|---------|--------|
| Many tenants cold-miss after restart | Increase `LoadWorkers` (≤ vCPU); ensure NVMe for `policy_dir` |
| RAM pressure | Lower `CacheSize`; enable warm tier when implemented |
| First-request latency for new tenant | Optional **preload** on fsnotify when `policy.db` appears (already debounced reload) |
| Same tenant thundering herd | Already handled by **singleflight** — no config change needed |

### Metrics (planned)

- `ztfp_policy_cache_size` — current LRU length  
- `ztfp_policy_cold_load_total` — cold loads completed  
- `ztfp_policy_cold_load_latency` — load duration histogram  
- `ztfp_policy_load_queue_depth` — jobs waiting on `loadCh`

---

<a name="related"></a>
## Related reading

| Document | Topic |
|----------|--------|
| [Scaling_Dataplane.md](./Scaling_Dataplane.md) | LRU, worker pool, 10k tenants |
| [What.md](./What.md) | Data plane request path |
| [Reading_sqlite_db.md](./Reading_sqlite_db.md) | `LoadFromDB` flow |
| [../../docs/policy_changes.md](../../docs/policy_changes.md) | Phase 1C registry design |
| [../../docs/tenant_policy_watcher.md](../../docs/tenant_policy_watcher.md) | fsnotify reload vs cold-load pool |
