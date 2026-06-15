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
- [Features](Documentation/Features)
- [SSL Decryption](Documentation/SSL_Interception/SSL_Decrypt)
- [SSL Do Not Decrypt](Documentation/SSL_Interception/SSL_DND)
- [Concurrency Model](Documentation/concurrency-model)
- [DLP Engine](Documentation/dlp-engine)
- [MCP Support](Documentation/mcp-support)
- [Policy Engine](Documentation/policy-engine)

### Running Proxy
- [How to Start](Documentation/HowToStart_Proxy_And_Client)
- [Sample Proxy Runs](Documentation/Sample_Runs)
- [Folder Structure](Documentation/Folder_Structure)