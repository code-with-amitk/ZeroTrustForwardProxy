## Data Plane
- Go code lies on dataplane which does actual policy processing.
- This will read sqlite3 db file created by controlplane and create a AST(Prefix Tree/Abstract syntax tree) representing tenant's policy map in memory. 

## Tenant Policy Model (Target)
### Terminal actions

Every rule evaluation eventually yields one of these **terminal actions** (applied to the connection or request after any configured inspection):

| Action | Meaning |
|--------|---------|
| **ALLOW** | Permit traffic; no block page |
| **BLOCK** | Deny traffic; return block/coach page or reset connection |
| **BYPASS** | Skip further proxy processing for this flow (e.g. no decrypt, no DLP) |
| **FWD** | Forward explicitly (may differ from default allow in logging or upstream routing) |
| **COACH** | Allow but show coaching / warning UI |
| **CONTINUE** | No decision on this rule — evaluate the next rule in priority order |

### Scan fallback (unscannable content)

When the data plane cannot inspect content — encrypted ZIP, password-protected Office/PDF, unreadable binary — administrators configure a **fallback** independent of the primary rule action:

| Fallback | Behavior |
|----------|----------|
| **Fallback Allow** | Treat as if scan succeeded; traffic proceeds (weak for threat/DLP posture) |
| **Fallback Alert** | Log/alert that content was uninspected; traffic proceeds |
| **Fallback Block** | Drop download/connection; alert administrator (file could not be verified) |

Fallback applies per RTP/DLP policy block (or globally within that block), not as a substitute for a missing terminal action on allow/block rules.

### Policy categories (separate JSON blocks)

Tenant policy is a **document envelope** with one block per category. Each block has its own rules, priorities, and compile path into SQLite (separate tables or `policy_type` column — design choice for Phase 1B implementation).

```
{
  "tenant_id": 1,
  "default_action": "ALLOW",
  "policies": {
    "rtp": { ... },
    "bypass": { ... },
    "egress_ip": { ... },
    "enterprise_browser": { ... }
  }
}
```

#### 1. Real-time Protection (RTP)

Covers inline security inspection on live traffic. **DLP is one RTP sub-capability**, not a standalone top-level action enum.

- Match on domain, method, user/group, content direction (upload/download).
- If DLP/threat inspection is enabled on the matched rule, run inspect → then apply terminal action or fallback on scan failure.
- RTP rules compile into the primary evaluation path in the Go data plane (Phase 1C).

#### 2. Bypass policies

Controls whether TLS is intercepted or passed through.

| Mode | Behavior |
|------|----------|
| **SSL DND (do not decrypt)** | Bypass decrypt — CONNECT tunnel forwarded without MITM |
| **SSL decrypt** | Normal MITM path; subsequent RTP rules apply on cleartext |

Bypass is evaluated **before** RTP/DLP on CONNECT, since there is nothing to inspect if traffic is not decrypted.

#### 3. Egress IP policy

Matches traffic leaving the enterprise using **egress source identity** — the IP address (or interface) the router/gateway uses for outbound packets. All hosts behind the same gateway share that egress IP.

- Rules match on egress IP, destination, protocol, or tenant scope.
- Terminal action: ALLOW / BLOCK / BYPASS / etc.
- Relevant for split-tunnel VPN, regional egress, and partner allow-lists.

#### 4. Enterprise Browser policy

Not a separate browser binary — **security features applied to managed/enterprise browser sessions** (policy, extensions, RBI integration).

- Constraints on which sites open in isolated vs native rendering.
- **RBI (Remote Browser Isolation):** remote render, safe content delivered to user device.
- Rules may reference browser profile, RBI pool, or isolation requirement.
- Evaluated when User-Agent / client signals indicate enterprise browser (Phase 1C+ integration).

### Evaluation order (conceptual)

```
JWT → tenant_id
  → load tenant policy.db
  → bypass (SSL DND vs decrypt?)     … CONNECT only
  → egress IP (if applicable)
  → enterprise browser (if signaled)
  → RTP rules (ordered priority)
       → optional DLP/MCP inspect
       → fallback if unscannable
       → terminal action or CONTINUE
  → default_action
```

### Request path

```
HTTP request
  → auth → Identity{User, TenantID}
  → registry.EngineFor(tenantID)
  → engine.Decide(domain, method) → allow | block | inspect_dlp | …
  → if inspect_dlp: inspector.InspectRequest (today, same process)
  → forward
```

Tenancy comes from **JWT `tenant_id`**, not from destination domain or source IP alone.
