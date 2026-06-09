package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"zerotrust-forward-proxy/utils"
)

// MCPRequest holds extracted MCP protocol information.
type MCPRequest struct {
	IsMCP         bool
	AgentID       string
	SessionID     string
	TraceID       string
	Version       string
	RPCMethod     string
	ArgumentsURL  string
	Invalid       bool
	InvalidReason string
}

var supportedMCPMethods = map[string]struct{}{
	"tools/call":     {},
	"tools/list":     {},
	"resources/read": {},
	"resources/list": {},
	"prompts/get":    {},
	"initialize":     {},
	"context/upload": {},
}

// JSONRPCRequest models a minimal JSON-RPC/MCP envelope used for robust detection.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      interface{}     `json:"id"`
}

// extractMCPInfo detects MCP protocol requests and extracts agent metadata.
//
// Inputs:
// - r: HTTP request object
//
// Outputs:
// - MCPRequest struct with MCP detection and metadata
//
// Assumptions:
// - MCP detection is based on JSON-RPC 2.0 envelope parsing and supported methods.
func (s *Server) extractMCPInfo(r *http.Request) MCPRequest {
	s.Logger.Debug(utils.GetFunctionName())

	mcp := MCPRequest{IsMCP: false}

	headerProtocolVersion := r.Header.Get("MCP-Protocol-Version")
	headerSessionID := r.Header.Get("MCP-Session-Id")
	legacyVersion := r.Header.Get("X-MCP-Version")
	legacySessionID := r.Header.Get("X-MCP-Session-ID")
	hasMCPHeader := headerProtocolVersion != "" || headerSessionID != "" || legacyVersion != "" || legacySessionID != ""

	if r.Body != nil {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			mcp.Invalid = true
			mcp.InvalidReason = "failed to read MCP JSON body"
			return mcp
		}
		// restore body for downstream consumers
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		if len(bodyBytes) == 0 {
			if hasMCPHeader {
				mcp.IsMCP = true
				mcp.Invalid = true
				mcp.InvalidReason = "missing MCP JSON body"
			}
		} else {
			var jr JSONRPCRequest
			if err := json.Unmarshal(bodyBytes, &jr); err == nil {
				if jr.JSONRPC == "2.0" && jr.Method != "" {
					if _, ok := supportedMCPMethods[jr.Method]; ok {
						mcp.IsMCP = true
						s.Logger.Debug("setted mcp true")
						mcp.RPCMethod = jr.Method
						if len(jr.Params) > 0 {
							var params map[string]any
							if err := json.Unmarshal(jr.Params, &params); err == nil {
								if args, ok := params["arguments"].(map[string]any); ok {
									if urlValue, ok := args["url"].(string); ok {
										mcp.ArgumentsURL = urlValue
									}
								}
							}
						}
					} else if hasMCPHeader {
						mcp.IsMCP = true
						mcp.Invalid = true
						mcp.InvalidReason = "unsupported MCP method"
					}
				} else if hasMCPHeader {
					mcp.IsMCP = true
					mcp.Invalid = true
					mcp.InvalidReason = "invalid MCP JSON-RPC envelope"
				}
			} else if hasMCPHeader {
				mcp.IsMCP = true
				mcp.Invalid = true
				mcp.InvalidReason = "failed to parse MCP JSON body"
			}
		}
	} else if hasMCPHeader {
		mcp.IsMCP = true
		mcp.Invalid = true
		mcp.InvalidReason = "missing MCP JSON body"
	}

	if mcp.IsMCP {
		// Extract MCP metadata when present.
		if headerProtocolVersion != "" {
			mcp.Version = headerProtocolVersion
		} else {
			mcp.Version = legacyVersion
		}
		mcp.AgentID = r.Header.Get("X-MCP-Agent-ID")
		if headerSessionID != "" {
			mcp.SessionID = headerSessionID
		} else {
			mcp.SessionID = legacySessionID
		}
		mcp.TraceID = r.Header.Get("X-MCP-Trace-ID")

		s.Logger.Debug("MCP Request Detected",
			"AgentID", mcp.AgentID,
			"SessionID", mcp.SessionID,
			"TraceID", mcp.TraceID,
			"Version", mcp.Version,
			"RPCMethod", mcp.RPCMethod,
			"ArgumentsURL", mcp.ArgumentsURL,
			"Invalid", mcp.Invalid,
			"InvalidReason", mcp.InvalidReason)
	}

	return mcp
}
