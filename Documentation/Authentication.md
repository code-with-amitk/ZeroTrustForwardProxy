- [Overview](#ov)
- [Identity established once, not every Login](#once)
    - [Phase 0 Enrollment at time of laptop Issuance, get client certificate (bob@acme.com)](#ph0)
    - [Phase 1 — This morning: Bob logs into the laptop (08:55)](#ph1)
    - [Phase 2 — Before Chrome opens: tunnel comes up (08:56)](#ph2)
    - [Phase 3 — Bob opens Chrome and goes to google.com(Browser have no PAC) (08:57)](#ph3)
    - [Phase 4 — Bob locks laptop, Carol logs in (multi-user laptop)](#ph4)
    - [Phase 5 - Carol uses the browser today (SAML session creation) (PAC File)](#ph5)
        - [Second site same day — Carol opens `github.com` (session reused)](#second)
- [How tenant Id is retrieved?](#how)


# Authentication and Tenant Identification

<a name=ov></a>
## Overview

- In Forward proxy like solution, Authentication is carried by external IDP and **JWT based tenant identification is not done**.
- This is because on hot path(data path), validating JWT token every time is time costly operation.
- Rather proxy banks on **session cookie** which is generated after successful authentication to IDP.
- For subsequent HTTP requests, browser presents session cookie and it serves as token to access internet access.

### [HTTP Authentication Flow](https://code-with-amitk.github.io/Networking/OSI-Layers/Layer-7/HTTP/HTTP_Authentication.html)
- [SAML Response, SAML Assertion](https://code-with-amitk.github.io/Languages/Markup/SAML/)

<a name=once></a>
## Identity established once, not every Login

<a name=ph0></a>
### Phase 0 Enrollment at time of laptop Issuance, get client certificate (bob@acme.com)
- IT admin Creates Netskope tenant `acme.com`; syncs users from Okta/Azure AD via SCIM. `bob@acme.com`, groups `[engineering, all-employees]`
- Registers `LAPTOP-7F3A` under tenant `acme`
- nsclient installed on Laptop with config: `tenant=acme`, `gateway=gateway-acme.goskope.com`
- Client (first run), Contacts management plane; proves device is managed. **Device ID** `LAPTOP-7F3A` registered under tenant `acme`
- Client (first run), Performs **mutual TLS**, Netskope issues a **client certificate** bound to `LAPTOP-7F3A`. Cert + private key in OS cert store / client secure storage
- Client (first run) Installs Netskope **SSL inspection root CA** on the laptop
- IdP enrollment mode, If IT used “enroll via IdP”, Bob signs into Okta **once** during first browser login. Links device `LAPTOP-7F3A` ↔ user `bob@acme.com` in Netskope

“Authenticate once” does **not** mean the user never authenticates anywhere. It means authentication is split into **two layers**:

<a name=ph1></a>
### Phase 1 — This morning: Bob logs into the laptop (08:55)
- Bob presses power, sees Windows login, enters AD password
- Windows authenticates Bob to **Active Directory** / Azure AD join | Creates **OS session**: logged-on user `ACME\bob` or UPN `bob@acme.com`
- Netskope Client Windows service starts automatically. Service runs as SYSTEM; watches for user logon events

<a name=ph2></a>
### Phase 2 — Before Chrome opens: tunnel comes up (08:56)
> still **before** any browser traffic.

- Netskope Client picks nearest POP via DNS / GSLB → `gateway-acme.goskope.com` (Frankfurt POP)
- **TLS handshake** with **client certificate**, Server verifies: cert issued to `LAPTOP-7F3A`, tenant `acme-corp` — **device authenticated**
- Client sends **tunnel registration** inside TLS `{ tenant: "acme-corp", user: "bob@acme.com", device_id: "LAPTOP-7F3A", groups: ["engineering","all-employees"] }`
- Data plane creates **tunnel session** Internal table: `tunnel_uuid_9f2b` → `{ tenant, user, groups, device }`
- Tunnel stays up for hours. Reconnects on sleep/wake; may refresh user if different person logs into same laptop (multi-user mode)

<a name=ph3></a>
### Phase 3 — Bob opens Chrome and goes to google.com(Browser have no PAC) (08:57)
- Bob types `google.com` in address bar. Chrome resolves `www.google.com` → `142.250.x.x`
- Chrome opens TCP `:443` to Google. **Netskope Client driver intercepts** the connection (WFP / redirect to local client)
- No login prompt. Client does **not** open a Netskope or Okta page
- Client encapsulates flow. Inner flow: `CONNECT www.google.com:443` sent **inside existing tunnel** `tunnel_uuid_9f2b`
- HTTPS to Google. Data plane may MITM with tenant CA, inspect SNI/URL, apply RTP/DLP

<a name=ph4></a>
### Phase 4 — Bob locks laptop, Carol logs in (multi-user laptop)
- Bob locks screen. Tunnel may stay up or pause depending on config 
- Carol logs into Windows. Client detects new OS user → `carol@acme.com`
- Client re-registers tunnel. New session `tunnel_uuid_x1` with **Carol’s** user + groups
- Carol opens google.com. Policy evaluated as **Carol**, not Bob

<a name=ph5></a>
### Phase 5 - Carol uses the browser today (SAML session creation) (PAC File)
- Carol opens Safari. Browser fetches PAC from `https://intranet.acme.com/proxy.pac`.
- PAC says HTTPS → `PROXY eproxy-acme-corp.goskope.com:8081`.
- Carol types `google.com`. Safari sends request to **Netskope proxy**, not Google directly.
- Proxy: no auth cookie for Carol’s browser → **HTTP 302** redirect to `authservice` / SAML Forward Proxy.
- [Session Cookie is recieved](https://code-with-amitk.github.io/Networking/OSI-Layers/Layer-7/HTTP/HTTP_Authentication.html)
- Browser redirected back to original `google.com` request

<a name=second></a>
#### Second site same day — Carol opens `github.com` (session reused)
- PAC → proxy again
- Request includes `Cookie: nspatoken=…`
- Proxy looks up cookie → `carol@acme.com` — **no Okta redirect**
- Policy evaluated; traffic forwarded

<a name=how></a>
## How tenant Id is retrieved?

### From Session Cookie
- Auth service recieve SAML assertion after auth success. Auth service (session cookie to assertion map), and store session cookie in the browser.
- Proxy stores this sessionCookie to tenantId mapping locally(after taking from auth service) with TTL.
    - **How auth knows TenantID?** From saml response and assertions.
- Every time request comes in containing session Cookie, tenantId is found in O(1) time.

### From nsclient Tunnel
```mermaid
sequenceDiagram
    autonumber
    actor User
    participant OS as Windows / macOS
    participant Browser
    participant Client as Netskope Client<br/>(OS driver + service)
    participant DP as Data Plane<br/>gateway-acme-corp.goskope.com
    participant PE as Policy Engine<br/>(tenant acme-corp)
    participant Google as www.google.com

    Note over User,Google: Phase A — Before browser (tunnel already authenticated)

    User->>OS: Log in (AD / Azure AD password)
    OS-->>Client: User session bob@acme.com
    Client->>Client: Read enrollment<br/>device LAPTOP-7F3A, client cert, tenant acme-corp
    Client->>DP: TLS connect + client certificate<br/>to gateway-acme-corp.goskope.com
    DP->>DP: Verify client cert → device LAPTOP-7F3A<br/>Map gateway FQDN → tenant_id 1001 (acme-corp)
    Client->>DP: Tunnel register metadata<br/>user=bob@acme.com<br/>groups=engineering,all-employees
    DP->>DP: Create tunnel session tunnel_uuid_9f2b<br/>{tenant_id:1001, user, groups, device}

    Note over User,Google: Phase B — User types google.com (no PAC, no browser proxy)

    User->>Browser: Open Chrome, type google.com
    Browser->>Browser: DNS www.google.com → 142.250.x.x
    Browser->>OS: TCP connect 142.250.x.x:443

    OS->>Client: WFP / redirect intercepts :443
    Note right of Client: Browser unaware of proxy.<br/>No PAC involved.

    Client->>DP: Encapsulate flow inside tunnel_uuid_9f2b<br/>inner: CONNECT www.google.com:443
    DP->>DP: Tenant + user from tunnel session<br/>tenant_id 1001, bob@acme.com<br/>(NOT parsed from Google URL)
    DP->>PE: Decide(tenant_id=1001, user, groups,<br/>domain=www.google.com, method=CONNECT)
    PE->>PE: Load policy snapshot for tenant 1001<br/>Match rules on domain / user / groups
    PE-->>DP: ALLOW (example)

    DP->>Google: Upstream CONNECT + TLS (MITM if configured)
    Google-->>DP: HTTP response
    DP-->>Client: Encapsulated response
    Client-->>Browser: TLS bytes (appears as direct Google)
    Browser-->>User: Google search page

    Note over User,Google: Phase C — Every later request same session

    User->>Browser: Click link on Google
    Browser->>OS: TCP :443 to Google IP
    OS->>Client: Intercept
    Client->>DP: Same tunnel_uuid_9f2b — no re-auth
    DP->>PE: Decide(tenant_id, user, domain, …)
    PE-->>DP: ALLOW / BLOCK / DLP inspect
```