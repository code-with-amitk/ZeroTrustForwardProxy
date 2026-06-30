- [Control Plane](#cp)
- [Data Plane](#dp)
-- [Why “control plane” vs “data plane”?](#why)
- [Flow](#flow)


# Planes

ztfp as of now is divided in to 2 planes:

<a href=cp></a>
## Control Plane (Slow Path)

- This is a python module which provides Policy REST API where policy.json file will arrive from tenant
- It provides Python compiler which accepts tenant JSON, validate structure/types, compile to SQLite, write artifacts to disk
```
policy.json -> [Control Plane]  -> /var/tenant/tenant-id/policy.db(sqlite3 file)
                Inspection
                Validation types
```

<a href=dp></a>
## Data Plane (Fast Path)
- ztfp (Go), it forward HTTP/CONNECT, resolve tenant, load policy DB → AST, enforce policy, invoke DLP inline today 
- Proxy **never parses raw JSON on the request hot path**. JSON is validated and compiled once at upload time; the data plane reads pre-built SQLite files and builds in-memory matchers from them.
- Splitting compile (Python) from enforce (Go) keeps heavy work off the proxy hot path and matches how routers, firewalls, and service meshes separate “configuration” from “forwarding.”

<a href=why></a>
### Why “control plane” vs “data plane”?

| | **Control plane** (Python + upload API) | **Data plane** (Go policy engine in ztfp) |
|--|----------------------------------------|------------------------------------------|
| **Purpose** | Accept, validate, and **compile** tenant policy | **Enforce** policy on live HTTP/CONNECT traffic |
| **When it runs** | When an admin uploads or updates policy (rare) | On **every request** (millions/sec at scale) |
| **Input** | Raw JSON from tenant | Pre-built `policy.db` + JWT `tenant_id` |
| **Output** | `policy.json`, `policy.db`, `policy.meta.json` on disk | Allow / block / fwd decision |
| **Latency budget** | Seconds acceptable | Microseconds required |
| **Failure mode** | Reject upload; previous policy stays active | Must not stall forwarding; use last good engine |

<a href=flow></a>
## Flow
```
| tenant_id | Example tenant |
|-----------|----------------|
| 1 | Google |
| 2 | Akamai US |
| 3 | Apple |

                    ┌──────────────────────────────────────┐
  Tenant admin      │  Policy Control Plane                 │
  POST policy.json  │  • REST endpoint                      │
        ───────────►│  • Python: schema + type validation   │
                    │  • Python: JSON → policy.db           │
                    │  • Write policies/{tenant_id}/        │
                    └──────────────┬───────────────────────┘
                                   │ policy.json + policy.db
                                   ▼
                    ┌──────────────────────────────────────┐
                    │  Policy store on local disk / EBS     │
                    │  /var/ztfp/policies/{tenant_id}/      │
                    └──────────────┬───────────────────────┘
                                   │ fsnotify / version bump
                                   ▼
  End-user HTTP     ┌──────────────────────────────────────┐
  via proxy :8080   │  ztfp                                 │
        ───────────►│  • JWT → tenant_id                    │
                    │  • TenantPolicyRegistry (LRU cache)   │
                    │  • Engine.LoadFromDB → AST in RAM     │
                    │  • Decide() → allow | fwd | block |.. │
                    │  • Inspector (DLP) inline on hot path │
                    └──────────────────────────────────────┘
```