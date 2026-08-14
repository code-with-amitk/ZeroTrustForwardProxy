# Zero Trust Forward Proxy (Production Ready)

- This is Production-oriented forward proxy: HTTP + HTTPS interception (MITM), identity-aware policy enforcement, basic DLP inspection, JSON audit logs, and Prometheus metrics.
- It is implemented entirely from public protocols, RFCs, open-source projects, and my own design decisions. I intentionally avoid using any proprietary code, policies, algorithms, or internal documentation.

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
- [Authentication](Documentation/Authentication.md): Enrollment at time of laptop Issuance, get client certificate. Using zftp Window's Client or PAC file(SAML)
- [Control Plane & Data Plane](./Documentation/ControlPlane_DataPlane/What.md)
    - Control Plane
        - [What](./Documentation/ControlPlane_DataPlane/ControlPlane/What.md)
        - [Converting db->json. Why Good for dataplane?](/Documentation/ControlPlane_DataPlane/ControlPlane/Converting_json_to_db.adoc)
    - Data Plane
        - [What](./Documentation/ControlPlane_DataPlane/Dataplane/What.md)
        - [DLP Inspection](./Documentation/ControlPlane_DataPlane/Dataplane/DLP_Inspection_Architecture.md)
        - Policy Load at runtime for Tenant
            - [Policy read from sqlite3 policy.db](./Documentation/ControlPlane_DataPlane/Dataplane/Reading_sqlite_db.md)
            - [500 Requests from Tenant whose context is not in Cache](./Documentation/ControlPlane_DataPlane/Dataplane/500_Requests_from_Tenant_whose_context_is_not_in_Cache.md)
- [Device Hardening, Steering](Documentation/Authentication/PAC_Zftp_Windows_Client_Hardening.md): Uninstall PAC, zftp Window's Client, zftp Window's Client crash, Traffic Steering when both zftp Window's Client are present 
- [Concurrency Model](Documentation/concurrency-model.md)
- Others
    - [DLP Engine](Documentation/dlp-engine.md)
    - [Support for UTF-8 Characters](Documentation/Support_For_UTF-8_Characters.md)
    - [Features List](Documentation/feature-flows.md)
    - SSL: [SSL Decryption](Documentation/SSL_Interception/SSL_Decrypt.adoc), [SSL Do Not Decrypt](Documentation/SSL_Interception/SSL_DND.adoc)
    - [MCP Support](Documentation/mcp-support.md)
- Scaling
    * Horizontal Scaling
        * [Introduction](Documentation/Horizontal_Scaling/Introduction.md)
        * [How to Scale](Documentation/Horizontal_Scaling/Kubernets/How_to_Scale.md)
        * [Kubernets Manifests](Documentation/Horizontal_Scaling/Kubernets/Manifests.md)
        * [Things to be Done](Documentation/Horizontal_Scaling/Kubernets/Things_to_be_Done.md)
    * Vertical Scaling
        * [Scaling Dataplane](./Documentation/ControlPlane_DataPlane/Dataplane/Scaling_Dataplane.md)
- [Observability](Documentation/Observability/Prometheus.md)
- Policy Engine
    - [What](Documentation/Policy_Engine/What.md)
    - [AST. How rules are stored?](Documentation/Policy_Engine/AST.md)
    - [Delta Policy Change](Documentation/Policy_Engine/DeltaPolicyChange.md)
    - [Policy Distribution (json(500MB) → sqlite(400MB) → gzip(50MB))](Documentation/Policy_Engine/Conversion_From_JSON_to_sqlitedb.md)

### Running Proxy
- [How to Start](Documentation/Commands.adoc)
- [Sample Proxy Runs](Documentation/Sample_Runs.adoc)
- [Folder Structure](Documentation/Folder_Structure.adoc)
