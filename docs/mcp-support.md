# MCP (Model Context Protocol) Support in Zero Trust Forward Proxy

## Overview

The Zero Trust Forward Proxy now includes comprehensive support for requests coming from AI agents using the Model Context Protocol (MCP), such as the Claude CLI agent. This document explains how the proxy identifies, authenticates, and applies policies to MCP requests.

## What is MCP?

The Model Context Protocol (MCP) is a protocol used by AI agents like Claude CLI to communicate with external services. MCP requests have specific characteristics:
- JSON-RPC 2.0-style request envelopes
- Structured `method`/`params` payloads for tool calls
- Session and trace tracking capabilities
- Agent identification metadata

## Request Identification

### Detection Mechanism

The proxy detects MCP requests by parsing the HTTP request body as a JSON-RPC envelope.
It only marks a request as MCP when:
- the body is valid JSON,
- the `jsonrpc` field equals `2.0`, and
- the `method` field matches a supported MCP method such as `tools/call`, `tools/list`, `resources/read`, `resources/list`, `prompts/get`, `initialize`, or `context/upload`.

The proxy then extracts inner request metadata from `params.arguments`, including the actual resource `url` if present.

### MCP Protocol Headers

The following headers identify and provide metadata for MCP requests, but they are not the primary detection mechanism:

| Header | Description | Example |
|--------|-------------|---------|
| `X-MCP-Version` | MCP protocol version | `1.0` |
| `X-MCP-Agent-ID` | Unique agent identifier | `claude-cli-v1` |
| `X-MCP-Request-Type` | Type of MCP request | `tool-call`, `context-upload` |
| `X-MCP-Session-ID` | Session identifier for correlation | `sess-12345abcde` |
| `X-MCP-Trace-ID` | Request trace identifier | `trace-9876543210` |

## Authentication & Identity Extraction

### JWT-Based Identity

MCP agents are authenticated via JWT tokens in the `Authorization` header:

```
Authorization: Bearer <JWT_TOKEN>
```

The JWT contains the agent identity (user claim). For MCP agents, this is typically:
```json
{
  "user": "mcp-agent",
  "tenant_id": 1
}
```

### User Identification Flow

1. Extract JWT token from Authorization/Proxy-Authorization header
2. Validate JWT signature
3. Extract `user` claim from JWT
4. Use user identity for policy evaluation

## Policy Enforcement

### Policy Rules for MCP Agents

Policies are defined in `policy.yaml` with user-based access control:

```yaml
# MCP Agent Policies
- user: "mcp-agent"
  domain: "api.example.com"
  action: allow
  
- user: "mcp-agent"
  domain: "*.internal.example.com"
  action: block
  
- user: "mcp-agent"
  domain: "internal-service.example.com"
  action: block
```

### Policy Evaluation Steps

1. **Identity Resolution**: Extract user from JWT
2. **Protocol Detection**: Identify if request is MCP
3. **Domain Matching**: Check target domain against policies
4. **Action Decision**: Return allow/block decision
5. **DLP Inspection**: Inspect request/response payloads
6. **Audit Logging**: Log decision with MCP metadata

### Domain Matching

Policies support flexible domain matching:
- Exact match: `api.example.com`
- Wildcard subdomains: `*.example.com`
- Wildcard all: `*`

## Request Processing Pipeline

```
HTTP Request
    ↓
[Parse JSON-RPC MCP envelope]
    ↓
[Extract MCP metadata and arguments.url]
    ↓
[Authenticate via JWT]
    ↓
[Identify User & Domain]
    ↓
[Evaluate Policy Rules]
    ↓
[Perform DLP Inspection]
    ↓
[Audit Log with MCP Metadata]
    ↓
[Forward or Block]
```

## Audit Logging

### MCP-Enhanced Audit Log

Audit logs include MCP-specific fields for comprehensive tracking:

```json
{
  "time": "2026-05-15T10:30:45Z",
  "user": "mcp-agent",
  "domain": "api.example.com",
  "method": "POST",
  "action": "allowed",
  "protocol": "HTTP+MCP",
  "agent_id": "claude-cli-v1",
  "session_id": "sess-12345abcde",
  "trace_id": "trace-9876543210",
  "latency_ms": 145,
  "status_code": 200,
  "violations": []
}
```

### Audit Fields

| Field | Purpose |
|-------|---------|
| `protocol` | Request protocol type (HTTP, HTTPS, HTTP+MCP, HTTPS+MCP) |
| `agent_id` | MCP agent identifier |
| `session_id` | MCP session for request correlation |
| `trace_id` | MCP trace ID for distributed tracing |

## Implementation Details

### Files Modified

1. **cmd/client/main.go**
   - Added MCP scenarios for testing
   - Simulates Anthropic-style JSON-RPC MCP requests
   - Tests policy enforcement for MCP agents

2. **proxy/server.go**
   - `extractMCPInfo()`: Detects MCP requests
   - `MCPRequest` struct: Holds MCP metadata
   - `logAuditWithMCP()`: Enhanced audit logging
   - Updated `handleHTTP()` and `handleHTTPS()`: MCP-aware handling

3. **policy.yaml**
   - Added MCP-specific policy rules
   - Restrictions for internal services
   - Allowed access for API endpoints

### Key Functions

#### extractMCPInfo(r *http.Request) → MCPRequest

Detects MCP protocol and extracts metadata:
- Parses the HTTP request body as a JSON-RPC 2.0 envelope
- Validates supported MCP methods such as tools/call, tools/list, resources/read, resources/list, prompts/get, initialize, and context/upload
- Extracts nested request arguments, including arguments.url for inner resource policy evaluation
- Reads X-MCP-* headers as metadata for auditing and tracing
- Returns MCPRequest struct with detection status

#### logAuditWithMCP(...)

Logs audit events with MCP protocol information:
- Includes protocol type
- Captures agent/session/trace IDs
- Provides distributed tracing support

## Testing MCP Support

### Test Scenarios in client/main.go

1. **MCP agent HTTP request - allowed**
   - Accesses allowed domain (api.example.com)
   - Expected: 200 OK

2. **MCP agent HTTP request - blocked domain**
   - Attempts access to internal-service.example.com
   - Expected: 403 Forbidden

3. **MCP agent POST request with DLP check**
   - Sends data containing sensitive patterns
   - Expected: 403 Forbidden (DLP violation)

4. **MCP agent HTTPS CONNECT - allowed**
   - HTTPS tunnel for allowed domain
   - Expected: 200 OK

### Running Tests

```bash
# Start proxy server
go run cmd/proxy/main.go

# In another terminal, run client with MCP scenarios
go run cmd/client/main.go
```

## Security Considerations

### DLP Enforcement for MCP

- All request/response bodies are inspected
- Sensitive patterns detected even for MCP agents
- Audit logs include violation details

### Session Isolation

- Each MCP session tracked via session_id
- Distributed tracing via trace_id
- Audit logs enable complete session reconstruction

### Rate Limiting

- MCP requests follow same policies as regular HTTP
- No special bypass for AI agents
- Default allow/block applies if no specific rule matches

## Future Enhancements

1. **MCP Version Support**: Handle different MCP protocol versions
2. **Agent Quota Management**: Rate limiting per agent
3. **Context-Aware Policies**: Policies based on MCP request type
4. **Enhanced Metrics**: MCP-specific Prometheus metrics
5. **MCP Response Streaming**: Support for streamed responses

## Troubleshooting

### MCP Requests Not Detected

Check:
1. User-Agent header contains "mcp-client" or "MCP"
2. X-MCP-Version header is present
3. Check proxy logs for "MCP Request Detected"

### Policy Not Applied

Verify:
1. User identity correctly extracted from JWT
2. Domain name matches policy rule pattern
3. Check policy.yaml for correct rules
4. Review audit logs for decision reason

### Missing Audit Fields

Ensure:
1. MCP headers are properly sent by client
2. Proxy extracts MCP info (check logs)
3. logAuditWithMCP is called for MCP requests
