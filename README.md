# Zero Trust Forward Proxy (Production Ready)

This is Production-oriented forward proxy inspired by Netskope/Zscaler patterns: HTTP + HTTPS interception (MITM), identity-aware policy enforcement, basic DLP inspection, JSON audit logs, and Prometheus metrics.

### What This Project Does
- Accepts HTTP proxy traffic and HTTPS `CONNECT` tunnels.
- Performs HTTPS interception by acting as an on-path TLS endpoint with dynamically issued per-domain certificates.
- Extracts identity from bearer JWT header (`Bearer token`), validates and allow access.
- Policy Enforcement: Enforces user/domain policies loaded from YAML.
- DLP Inspection: Inspects request/response payloads for sensitive data patterns (credit card and secret-like values).
- Emits structured JSON logs, Prometheus metrics.
- Provides coaching Content/Block page back to the user

## Documentation and Diagrams
- [Architecture](Documentation/architecture.md)
- [Features](Documentation/feature-flows.md)
- [SSL Decryption](Documentation/SSL_Interception/SSL_Decrypt.adoc)
- [SSL Do Not Decrypt](Documentation/SSL_Interception/SSL_DND.adoc)
- [Concurrency Model](Documentation/concurrency-model.md)
- [DLP Engine](Documentation/dlp-engine.md)
- [MCP Support](Documentation/mcp-support.md)
- Horizontal Scaling
    - [Introduction](Documentation/Horizontal_Scaling/Introduction.md)
    - [How to Scale](Documentation/Horizontal_Scaling/Kubernets/How_to_Scale.md)
    - [Kubernets Manifests](Documentation/Horizontal_Scaling/Kubernets/Manifests.md)
    - [Things to be Done](Documentation/Horizontal_Scaling/Kubernets/Things_to_be_Done.md)
- Vertical Scaling
    - [Scaling Dataplane](./Documentation/ControlPlane_DataPlane/Dataplane/Scaling_Dataplane.md)
- [Observability](Documentation/Observability/Prometheus.md)
- Policy Engine
    - [What](Documentation/Policy_Engine/What.md)
    - [AST](Documentation/Policy_Engine/AST.md)
    - [Delta Policy Change](Documentation/Policy_Engine/DeltaPolicyChange.md)
- [Control Plane & Data Plane](./Documentation/ControlPlane_DataPlane/What.md)
- Control Plane
    - [What](./Documentation/ControlPlane_DataPlane/ControlPlane/What.md)
- Data Plane
    - [What](./Documentation/ControlPlane_DataPlane/Dataplane/What.md)
    - [DLP Inspection](./Documentation/ControlPlane_DataPlane/Dataplane/DLP_Inspection_Architecture.md)
    - [Policy read from sqlite3 policy.db](./Documentation/ControlPlane_DataPlane/Dataplane/Reading_sqlite_db.md)

### Running Proxy
- [How to Start](Documentation/Commands.adoc)
- [Sample Proxy Runs](Documentation/Sample_Runs.adoc)
- [Folder Structure](Documentation/Folder_Structure.adoc)
