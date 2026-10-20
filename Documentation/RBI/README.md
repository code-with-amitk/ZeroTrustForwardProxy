- [Flow](#Flow)
    - [How Policy Engine decides to Isolate?](#How)
    - [Is the container already running?](#container)
    - [How Risk Score is Calculated?](#RiskScore)

# RBI
- RBI is per website(eg: malware, phishing). All web traffic from browser is never isolated. Rendering every web page via remote containers consumes massive cloud compute, bandwidth, and memory resources.
- RBI is triggered based on RISK SCORE and URL CATEGORIZATION.
- Examples of Malware & Phishing Categories that Trigger RBI:
** Newly Registered Domains (NRDs): Domains registered within the last 7 to 30 days. Attackers frequently spin up fresh domains for spear-phishing or watering-hole attacks.
** Uncategorized / Parking Domains: Sites that have no threat intelligence history yet. Because they are unknown, they are treated as high-risk.
** Phishing Sites: Eg: sites mimicking corporate login portals. eg: login-microsoft.in

<a name=Flow></a>

## Flow
```mermaid
sequenceDiagram
    autonumber
    actor Client as Client (Standard Browser)
    box ztfp
    participant GW as ztfpClient GW<br>PAC File GW
    participant Conn as Connector
    participant PE as Policy Engine
    participant RS as Risk Score<br>ML<br>Threat Intelligence
    participant RBI as Remote Browser<br>Container<br><br>Agent -> Chromium
    
    end
    participant Origin as Origin Web Server

    Note over Client, GW: 1. User enters URL & sends HTTPS Request
    Client->>GW: HTTP CONNECT or GET /path<br/> Headers:<br>Host: example.com,<br>User-Agent: Chrome,<br>SessionCookie: 123

    Note over GW: GW extracts HTTP<br>Header info
    GW->>Conn: Event Msg <br>{<br>URL: example.com,<br>Category: Uncategorized,<br>User: John Doe<br>}
    Conn->>PE: Event Msg
    PE->>RS: Event Msg
    Note over RS: Calculate Risk Score<br>0..100
    RS-->>PE: Risk:90
    Note over PE: Decision Taken based on:<br>Policy<br>Matching Header<br>Risk Score<br>URL Category
    PE-->Conn: MATCH: Action = Isolate (Route to RBI)

    Note over Conn: Redirects session<br>to Cloud Container
    Conn->>RBI: HTTP CONNECT or GET /path<br/> Headers:<br>Host: example.com,<br>User-Agent: Chrome
    
    Note over RBI: HTTP recieved by<br>Agent running(in container)
    Note over RBI:Agent sends req<br>to Chromium browser(in Container)<br><br>Chromium fetches content from Origin
    RBI->>Origin: GET /path HTTP/1.1 <br/> Headers: Host: example.com, User-Agent: RBI-Agent
    Origin-->RBI: HTTP/1.1 200 OK <br/> Headers: Content-Type: text/html,<br>Content Length: 45KB <br/> Body: HTML/JS/CSS payloads

    Note over RBI: RBI sanitizes<br>Stream to Client
    RBI-->>Conn: HTTP/1.1 200 OK (Rewritten HTML / Isolation Wrapper / WebSocket Stream) <br/> Headers: Content-Type: text/html, X-Isolated: true
    Conn-->>Client: Stream / Sanitized DOM & Pixels <br/> Headers: HTTP/1.1 200 OK,<br>Cache-Control: no-store
```

<a name=how></a>

### How Policy Engine decides to Isolate?
**if any of below categories is satisfied:**

- if target URL(retrieved from [Host Header](https://code-with-amitk.github.io/Networking/OSI-Layers/Layer-7/HTTP/HTTP%20Headers.html#HostHeader)) is Uncategorized/Newly Registered/high-risk categories (e.g: Phishing, Malware).
- if user belongs to protected groups eg(Finance) he gets isolated for high-risk sites
- Unmanaged devices(BYOD) frequently trigger default RBI for all web traffic

<a name=container></a>

### Is the container already running?
- Yes. zftp proxy maintains Pool of containers which are already running.
- Inside the container a mini secure browser(such as Chromium or Firefox) runs

<a name=RiskScore></a>

### How Risk Score is Calculated?
- 0 = completely trustworthy and 100 = known malicious
```
Risk Score = w_1(Domain Age) + w_2(SSL Posture) + w_3(Hosting Infra) + w_4(Threat History) + w_5(Content Heuristics)

Domain Age: Registered 3 days ago	= +35 points (Newly Registered Domain)
Top-Level Domain (TLD)	.top (High abuse rate)	+15 points (Suspicious TLD)
SSL/TLS Certificate	Free Let's Encrypt, issued 1 hour ago	+15 points (Short-lived / low trust cert)
```

<a name=EnterpriseBrowser></a>

## RBI Require an Enterprise Browser => No?
- RBI works With standard Browsers(Chrome, Firefox) as well. Traffic sent via zftp Client or explicit proxy/PAC files.