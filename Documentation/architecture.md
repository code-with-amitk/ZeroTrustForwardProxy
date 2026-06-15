# Architecture Diagram

```mermaid
flowchart LR
    C[Client Browser/App] -->|HTTP/CONNECT| P[Proxy Listener :8080]
    P --> A[Identity Layer JWT Extract/Validate]
    A --> PE[Policy Engine YAML Rules]
    PE --> I[DLP Inspector]
    I --> UP[Upstream Server]
    P --> L[JSON Audit Logger]
    P --> M[Prometheus Metrics]
    M --> PM[metrics :9090]
    P --> CA[Dynamic Cert Authority]
```

## Notes
- Proxy runs as `net/http` server with explicit `CONNECT` MITM handling.
- CA module auto-creates root CA and issues per-domain leaf certs (cached in memory).
- Policy and DLP are enforced before upstream forwarding for both HTTP and HTTPS-decrypted traffic.
