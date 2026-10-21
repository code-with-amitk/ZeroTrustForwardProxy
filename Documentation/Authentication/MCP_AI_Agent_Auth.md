- [Flow](#flow)
-- [Protected Resource Metadata (PRM)](#prm)


<a name=flow></a>

## Flow
```mermaid

sequenceDiagram
    autonumber
    participant User as Browser
    participant Client as Claude Code CLI
    participant Proxy as ZT Forward Proxy
    participant MCP as Remote MCP Server
    participant DB as Backend Database
    participant IdP as IDP OKTA

    Note over Client: Request Tools List
    Client->>Proxy: POST /mcp HTTP/1.1 Host: mcp.company.com<br/>{"method":"tools/list}
    Note over Proxy: Is method:tools/list allowed?<br>Yes
    Proxy->>MCP: POST /mcp HTTP/1.1 Host: mcp.company.com<br/>{"method":"tools/list}
    Note over MCP: Does MCP Client have<br>Access Token<br>No
    Note over MCP: Send<br>Protected Resource Metadata(PRM)<br>in WWW-Authenticate header
    MCP-->>Proxy: HTTP/1.1 401 Unauthorized<br/>WWW-Authenticate: "https://mcp.company.com/<br>.well-known/oauth-protected-resource"
    Proxy-->>Client: HTTP/1.1 401 Unauthorized<br/>WWW-Authenticate: "https://mcp.company.com/<br>.well-known/oauth-protected-resource"

    Note over Client: Get Access token from<br>WWW-Authenticate endpoint
    Client->>Proxy: HTTP/1.1. GET /.well-known/oauth-protected-resource
    Proxy->>MCP: HTTP/1.1 GET /.well-known/oauth-protected-resource
    MCP-->>Proxy: HTTP/1.1 200 OK {https://okta.com}
    Proxy-->>Client: HTTP/1.1 200 OK {https://okta.com}

    Client->>Proxy: HTTP/1.1 GET https://okta.com
    Proxy->>IdP: HTTP/1.1 https://okta.com
    Note over IdP: Generate challenge
    IdP-->>Proxy: HTTP/1.1 200 OK<br/>{"authorization_endpoint":"/authorize",<br>"token_endpoint":"/token",<br>"jwks_uri":"/jwks",<br>"code_challenge_methods":["XXX"]}
    Proxy-->>Client: HTTP/1.1 200 OK data

    Note over Client: Find hash of challenge<br>send Hash
    Note over Client: Calculate code=SHA256(XXX)

    Client->>Proxy: HTTP/1.1 GET /authorize?code
    Proxy->>IdP: HTTP/1.1 GET /authorize?code
    Note over IdP: Hash Good

    IdP->>User: Display login, Password
    User-->>IdP: User, Password, MFA
    Note over IdP: Generate<br>1. Session Cookie<br>2.Authorization Code
    IdP->>User:1. Session Cookie, 2.Authorization Code
    Note over User: Session Cookie<br>stored in browser

    User->>Client:Authorization Code(YYY)
    Client->>Proxy: HTTP/1.1 POST /token, AuthCode=YYY<br/>Host: auth.company.com
    Proxy->>IdP: HTTP/1.1 POST /token, AuthCode=YYY <br/>Host: auth.company.com
    IdP->>IdP: Validate Authorization code<br><br>Generate Access Code=AAA
    IdP-->>Proxy: HTTP/1.1 200 OK<br/>{"Bearer_Token":"AAA","expires_in":3600}
    Proxy-->>Client: HTTP/1.1 200 OK<br/>{"Bearer_Token":"AAA","expires_in":3600}

    Client->>Proxy: POST /mcp HTTP/1.1<br/>{"Bearer_Token":"AAA", respource: "DB"}
    Note over Proxy: Is Tool=DB allowed<br>Yes
    Proxy->>MCP: POST /mcp HTTP/1.1<br/>{"Bearer_Token":"AAA", respource: "DB"}
    MCP->>MCP: Validate Bearer Token<br>expiry
    MCP->>DB: Execute SQL query<br/>SELECT * from
    DB-->>MCP: Query result set
    MCP-->>Proxy: HTTP/1.1 200 OK {SELECT * from result}
    Proxy-->>Client: HTTP/1.1 200 OK {SELECT * from result}
```

<a name=prm></a>

## Protected Resource Metadata (PRM)
- For very 1st time when AI Agent(MCP Client) connects to MCP server(via zftp), using <code>HTTP POST<code>, MCP server finds request does not have valid access token, then MCP server sends PRM in <code>WWW-Authenticate</code> header.
```
{
  "resource": "https://mcp.company.com",
  "authorization_servers": ["https://auth.company.com"]
}
```
- It tells AI Agent(Eg Claude Code) which authorization server can issue tokens for this MCP resource.