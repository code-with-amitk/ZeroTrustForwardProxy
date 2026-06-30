# Policy Control Plane

Python service that validates tenant policy JSON and compiles it to SQLite. Runs separately from the ztfp forward proxy (data plane).

## Why control plane vs data plane?

| | Control plane (this service) | Data plane (ztfp Go proxy) |
|--|------------------------------|----------------------------|
| **When it runs** | On policy upload / admin change | On every HTTP/CONNECT request |
| **Work** | JSON Schema, type checks, regex compile, SQLite build | Load `.db`, build AST, `Decide()`, forward traffic |
| **Latency tolerance** | Seconds (batch compile) | Microseconds |
| **Failure impact** | Upload rejected; running policy unchanged | Request blocked or allowed |

The control plane is **slow path, administrative**. The data plane is **fast path, operational**. Splitting them keeps compile and validation off the request hot path.

## Tenant IDs

Tenants are identified by **positive integers** (e.g. `1` = Google, `2` = Akamai US, `3` = Apple). Artifacts are stored under:

```
/var/ztfp/policies/{tenant_id}/policy.json
/var/ztfp/policies/{tenant_id}/policy.db
/var/ztfp/policies/{tenant_id}/policy.meta.json
```

## Setup

```bash
cd controlplane
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run API

```bash
export ZTFP_POLICY_DIR=/var/ztfp/policies/
export CONTROL_PLANE_API_TOKEN=changeme   # optional; omit for open dev mode
python -m api.server
```

Listens on `127.0.0.1:8090` by default (`CONTROL_PLANE_HOST`, `CONTROL_PLANE_PORT`).

## Compile JSON to SQLite (local / offline)

Use this when testing the Go data plane without the upload API. Place `policy.json` in any folder, compile from `controlplane/`, then copy the `.db` to the tenant policy store.

```bash
cd controlplane
source .venv/bin/activate

# Folder containing policy.json → writes policy.db + policy.meta.json beside it
mkdir -p work
cp ../testdata/sample_policy_rtp.json work/policy.json
python -m policy_compiler.cli work/

# Or compile a JSON file directly (writes policy.db beside that file)
python -m policy_compiler.cli ../testdata/sample_policy_rtp.json

# Install to tenant store for ztfp (tenant_id = 1)
mkdir -p /var/ztfp/policies/1
cp work/policy.json work/policy.db /var/ztfp/policies/1/
```

**Output (same folder as `policy.json`):**

| File | Purpose |
|------|---------|
| `policy.db` | Compiled SQLite consumed by Go `LoadFromDB` |
| `policy.meta.json` | Checksum, rule count, schema version (optional; omit with `--no-meta`) |

**Options:** `--rewrite-json` (normalize legacy flat JSON in place), `--no-meta`, `--db /path/to/out.db`

Sample JSON (one block each): `../testdata/sample_policy_rtp.json`, `sample_policy_bypass.json`, `sample_policy_egress_ip.json`, `sample_policy_enterprise_browser.json`.

## Upload policy (API)

Policy documents use a **`policies` envelope** with blocks: `rtp`, `bypass`, `egress_ip`, `enterprise_browser`. Terminal actions are `ALLOW`, `BLOCK`, `BYPASS`, `FWD`, `COACH`, `CONTINUE`. DLP/MCP are **inspection triggers** inside RTP rules, not action enum values.

Legacy flat JSON (`default_action` + top-level `rules[]`) is still accepted and normalized to `policies.rtp` on upload.

```bash
curl -X POST http://127.0.0.1:8090/api/v1/tenants/1/policy \
  -H "Authorization: Bearer changeme" \
  -H "Content-Type: application/json" \
  -d @../testdata/tenant_policy_sample.json
```

See `docs/extending_rtp_conditions.md` for adding new RTP condition fields (e.g. `saml_groups`).

## Tests

```bash
cd controlplane
pytest tests/ -v
```
