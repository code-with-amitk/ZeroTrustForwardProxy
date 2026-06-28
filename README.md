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
### Understanding Proxy
- [Architecture](Documentation/architecture.md)
- [Features](Documentation/Features.md)
- [SSL Decryption](Documentation/SSL_Interception/SSL_Decrypt.adoc)
- [SSL Do Not Decrypt](Documentation/SSL_Interception/SSL_DND.adoc)
- [Concurrency Model](Documentation/concurrency-model.md)
- [DLP Engine](Documentation/dlp-engine.md)
- [MCP Support](Documentation/mcp-support.md)
- [Policy Engine](Documentation/policy-engine.md)
- Horizontal Scaling
    - [Introduction](Documentation/Introduction.md)
    - [How to Scale](Documentation/Horizontal_Scaling/Kubernets/How_to_Scale.md)
    - [Kubernets Manifests](Documentation/Horizontal_Scaling/Kubernets/Manifests.md)
    - [Things to be Done](Documentation/Horizontal_Scaling/Kubernets/Things_to_be_Done.md)
- [Observability](Documentation/Observability)

### Running Proxy
- [How to Start](Documentation/HowToStart_Proxy_And_Client.adoc)
- [Sample Proxy Runs](Documentation/Sample_Runs.adoc)
- [Folder Structure](Documentation/Folder_Structure.adoc)
