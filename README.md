# Zero Trust Forward Proxy (Go)

This is Production-oriented forward proxy inspired by Netskope/Zscaler patterns: HTTP + HTTPS interception (MITM), identity-aware policy enforcement, basic DLP inspection, JSON audit logs, and Prometheus metrics.

## What This Project Does
- Accepts HTTP proxy traffic and HTTPS `CONNECT` tunnels.
- Performs HTTPS interception by acting as an on-path TLS endpoint with dynamically issued per-domain certificates.
- Extracts identity from bearer JWT header (`Authorization`) with mock validation.
- Enforces user/domain policies loaded from YAML.
- Inspects request/response payloads for sensitive data patterns (credit card and secret-like values).
- Emits structured JSON logs and Prometheus metrics.

## Folder Structure Overview
- `cmd/proxy/` - CLI entrypoint (`main.go`) for startup/config wiring.
- `proxy/` - Core proxy runtime, CONNECT MITM handling, CA/cert issuance, request forwarding.
- `auth/` - JWT extraction and validation interface + mock validator.
- `policy/` - YAML-driven policy engine (user/domain allow/block rules).
- `inspector/` - DLP inspection module and violation model.
- `metrics/` - Prometheus counters/histograms and HTTP metrics handler.
- `config/` - YAML config loader with sane defaults.
- `docs/` - Architecture and flow diagrams.
- `policy.yaml` - Example policy file.
- `config.yaml` - Example runtime config.

## Local Run Instructions
1. Ensure Go 1.22+ is installed.
2. Install dependencies:
   - `go mod tidy`
3. Start proxy:
   - `go run ./cmd/proxy -config config.yaml`
4. Configure client/app/browser to use proxy at `localhost:8080`.
5. Import generated root CA (`ca.crt`) into your test client trust store for HTTPS MITM.
6. Scrape metrics at:
   - `http://localhost:9090/metrics`

## Example Identity Token
- Header format: `Authorization: Bearer valid:alice`
- `valid:<user>` is treated as authenticated user in this mock.
- Missing/invalid format falls back to `anonymous`/`unknown` semantics.

## Example Policy Behavior
- Rules are first-match-wins.
- Supports wildcard users (`*`) and wildcard domains (`*.example.com`).
- Set `default_action` to `allow` or `block`.

## Unit Tests
- Run all tests:
  - `go test ./...`
- Included tests:
  - `auth/` validator behavior
  - `policy/` domain matching logic
  - `inspector/` DLP detection logic

## Documentation and Diagrams
- `docs/architecture.md`
- `docs/feature-flows.md`
- `docs/policy-engine.md`
- `docs/dlp-engine.md`
- `docs/concurrency-model.md`

## Notes for Production Hardening
- Replace mock JWT validator with signature/issuer/audience validation (JWKS).
- Add domain allowlists for MITM bypass when needed.
- Add L7 protocol-aware parsers beyond regex DLP.
- Add rate limiting, mTLS between components, and persistent audit sink.

## How to start
### Server
```
PROXY_LOG_LEVEL=debug go run cmd/proxy/main.go
```

### Client
```
go run cmd/client/main.go
```
