// Package proxy contains the core forward-proxy data plane.
//
// This file implements request orchestration, including:
// - HTTP proxy forwarding
// - HTTPS CONNECT interception with MITM decryption/re-encryption
// - Identity extraction + policy decision + DLP enforcement pipeline
// - JSON audit logging and metrics observation
//
// Architecture fit:
//   - `cmd/proxy/main.go` composes this server with config and dependencies.
//   - This module is the central coordinator that executes security controls in
//     request path before any upstream communication.
//
// Design decisions:
// - `net/http` is used for listener lifecycle and standard HTTP path.
// - CONNECT paths are manually hijacked to implement TLS MITM.
// - Shared upstream transport enables connection pooling and low overhead.
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"zerotrust-forward-proxy/auth"
	"zerotrust-forward-proxy/config"
	"zerotrust-forward-proxy/inspector"
	"zerotrust-forward-proxy/metrics"
	"zerotrust-forward-proxy/policy"
	"zerotrust-forward-proxy/utils"

	"go.uber.org/zap"
)

// AuditLog is the structured JSON record for each request decision.
type AuditLog struct {
	Time       time.Time              `json:"time"`
	User       string                 `json:"user"`
	TenantID   string                 `json:"tenant_id,omitempty"`
	Domain     string                 `json:"domain"`
	Method     string                 `json:"method"`
	Action     string                 `json:"action"`
	Reason     string                 `json:"reason,omitempty"`
	LatencyMS  int64                  `json:"latency_ms"`
	StatusCode int                    `json:"status_code,omitempty"`
	Violations []inspector.Violation  `json:"violations,omitempty"`
	Extra      map[string]interface{} `json:"extra,omitempty"`
	SourceFile string                 `json:"source_file,omitempty"`
	SourceFunc string                 `json:"source_func,omitempty"`
	SourceLine int                    `json:"source_line,omitempty"`
	Protocol   string                 `json:"protocol,omitempty"`   // e.g., "HTTP", "HTTPS", "MCP"
	AgentID    string                 `json:"agent_id,omitempty"`   // For MCP agents
	SessionID  string                 `json:"session_id,omitempty"` // For MCP session tracking
	TraceID    string                 `json:"trace_id,omitempty"`   // For request tracing
}

// Server orchestrates proxy request handling and security enforcement.
type Server struct {
	Cfg                     config.Config
	Ca                      *CertificateAuthority
	Auth                    auth.Validator
	Policy                  *policy.Engine
	Inspector               *inspector.Inspector
	Metrics                 *metrics.Collector
	Logger                  *zap.SugaredLogger
	Transport               *http.Transport
	BlockPage               string
	mitmCertCache           map[string]*tls.Certificate
	mitmCertCacheMu         sync.RWMutex
	upstreamRevocationCache map[string]*revocationEntry
	upstreamRevocationMu    sync.RWMutex
	// httpSrv is the live net/http server; held so Shutdown() can drain it gracefully.
	httpSrv *http.Server
}

// Create a new Proxy server
func New(cfg config.Config, ca *CertificateAuthority, authz auth.Validator, pe *policy.Engine, dlp *inspector.Inspector, m *metrics.Collector, l *zap.SugaredLogger) *Server {
	// Configure HTTP for connection reuse and throughput.
	tr := &http.Transport{
		Proxy:                 nil,
		MaxIdleConns:          cfg.MaxIdleConns,
		MaxIdleConnsPerHost:   cfg.MaxIdleConnsPerHost,
		IdleConnTimeout:       cfg.IdleConnTimeout,
		ResponseHeaderTimeout: cfg.RequestTimeout,
		ForceAttemptHTTP2:     true,
	}
	// Return server
	blockPage, err := loadBlockPageTemplate(l)
	if err != nil {
		l.Warnf("failed to load block page template: %v", err)
	}

	server := &Server{
		Cfg:                     cfg,
		Ca:                      ca,
		Auth:                    authz,
		Policy:                  pe,
		Inspector:               dlp,
		Metrics:                 m,
		Logger:                  l,
		Transport:               tr,
		BlockPage:               blockPage,
		mitmCertCache:           map[string]*tls.Certificate{},
		upstreamRevocationCache: map[string]*revocationEntry{},
	}
	server.Transport.TLSClientConfig = server.newUpstreamTLSConfig()
	return server
}

func (s *Server) getMITMCertificate(host string) (*tls.Certificate, error) {
	host = stripPort(host)

	s.mitmCertCacheMu.RLock()
	if cert, ok := s.mitmCertCache[host]; ok {
		s.mitmCertCacheMu.RUnlock()
		s.Metrics.RecordCertCacheHit()
		s.Logger.Debug("MITM cert cache hit", "host", host)
		return cert, nil
	}
	s.mitmCertCacheMu.RUnlock()

	s.Metrics.RecordCertCacheMiss()
	s.Logger.Debug("MITM cert cache miss", "host", host)

	issued, err := s.Ca.IssueForHost(host)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(issued.CertPEM, issued.KeyPEM)
	if err != nil {
		return nil, err
	}

	s.mitmCertCacheMu.Lock()
	s.mitmCertCache[host] = &pair
	s.mitmCertCacheMu.Unlock()

	return &pair, nil
}

func (s *Server) newMITMTLSConfig(defaultHost string) *tls.Config {
	return &tls.Config{
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := stripPort(hello.ServerName)
			if host == "" {
				host = defaultHost
			}
			return s.getMITMCertificate(host)
		},
	}
}

// Listen binds the configured TCP address and returns the listener.
// Call Serve(ln) afterwards to begin accepting connections.
// Separating bind from serve lets callers signal readiness after the port
// is bound but before the first connection is accepted.
func (s *Server) Listen() (net.Listener, error) {
	srv := &http.Server{
		Addr:              s.Cfg.ListenAddr,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
	}
	s.httpSrv = srv

	ln, err := net.Listen("tcp", s.Cfg.ListenAddr)
	if err != nil {
		return nil, err
	}
	return ln, nil
}

// Serve accepts connections on ln and blocks until the server is shut down.
// Returns http.ErrServerClosed after a successful graceful shutdown.
func (s *Server) Serve(ln net.Listener) error {
	return s.httpSrv.Serve(ln)
}

// Start is a convenience wrapper: bind then serve in one call.
// It exists for simple use-cases (tests, local dev) where the ready-signal
// split provided by Listen()+Serve() is not needed.
func (s *Server) Start() error {
	ln, err := s.Listen()
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Shutdown drains in-flight requests and closes the listener.
// ctx controls the maximum wait time; pass a 30 s context for rolling updates.
// After Shutdown returns, Serve() unblocks with http.ErrServerClosed.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpSrv == nil {
		return nil
	}
	s.Logger.Info("proxy shutting down — draining in-flight requests")
	return s.httpSrv.Shutdown(ctx)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.Logger.Debug("r.Method: ", r.Method)

	// HTTP CONNECT is the tunnel setup message. Client sends:
	// CONNECT example.com:443 HTTP/1.1
	// We respond with 200, hijack the raw TCP connection, wrap it
	// inside our own TLS server using our CA, Client believes its
	// talking directly to example.com.
	if strings.EqualFold(r.Method, http.MethodConnect) {
		s.handleHTTPS(w, r)
		return
	}
	// Handle regular HTTP requests through standard forwarding path.
	s.handleHTTP(w, r)
}

// HTTP Request
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Extract MCP protocol information if present
	mcp := s.extractMCPInfo(r)
	protocol := s.FindProtocol(r, mcp)
	version := mcp.Version

	// Validate malformed MCP payloads before policy enforcement.
	if mcp.IsMCP && mcp.Invalid {
		reason := "invalid MCP request"
		if mcp.InvalidReason != "" {
			reason = mcp.InvalidReason
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(s.renderBlockPage(reason)))
		s.logAuditWithMCP(start, "", "", targetDomain(r), r.Method, "blocked", reason, http.StatusBadRequest, nil, mcp, protocol)
		return
	}

	// Policy Application, DLP Inspection
	user, tenantID, domain, blocked, status, reason, violations := s.evaluate(r, mcp, protocol, version)
	s.Logger.Debug("user: ", user, ", tenant: ", tenantID, ", Domain: ", domain, ", blocked: ", blocked, ", status: ", status, ", reason: ", reason, ", violations: ", violations)

	// Metrics Emission
	defer s.Metrics.Observe(start, blocked, user, domain)
	if blocked {
		// Return a coaching HTML page for policy/DLP denials.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(s.renderBlockPage(reason)))

		// Log with MCP information if applicable
		if mcp.IsMCP {
			s.logAuditWithMCP(start, user, tenantID, domain, r.Method, "blocked", reason, http.StatusForbidden, violations, mcp, protocol)
		} else {
			s.logAudit(start, user, tenantID, domain, r.Method, "blocked", reason, http.StatusForbidden, violations)
		}
		return
	}

	// Clone request object so proxy can safely mutate forwarding fields.
	outReq := cloneRequest(r)
	if outReq.URL.Scheme == "" {
		// Default missing scheme to HTTP for absolute-path style proxy requests.
		outReq.URL.Scheme = "http"
	}
	if outReq.URL.Host == "" {
		// Recover host from incoming request if URL host was not set.
		outReq.URL.Host = r.Host
	}
	// Clear RequestURI because client-side form is invalid for RoundTrip.
	outReq.RequestURI = ""

	s.Logger.Debug("Sending request: ", outReq)
	// Forward request to upstream destination using shared connection pool.
	resp, err := s.Transport.RoundTrip(outReq)
	s.Logger.Debug("Response: ", resp)

	if err != nil {
		// Surface upstream connectivity errors as bad gateway.
		http.Error(w, err.Error(), http.StatusBadGateway)
		// Audit gateway failure as blocked outcome for observability.
		if mcp.IsMCP {
			s.logAuditWithMCP(start, user, tenantID, domain, r.Method, "blocked", err.Error(), http.StatusBadGateway, violations, mcp, "HTTP+MCP")
		} else {
			s.logAudit(start, user, tenantID, domain, r.Method, "blocked", err.Error(), http.StatusBadGateway, violations)
		}
		return
	}
	// Ensure upstream response body resources are released.
	defer resp.Body.Close()

	// Copy all upstream headers to downstream response writer.
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	// Mirror upstream status code.
	w.WriteHeader(resp.StatusCode)
	// Stream upstream response body to client.
	_, _ = io.Copy(w, resp.Body)
	status = resp.StatusCode

	s.Logger.Debug("Response: ", resp)

	// Record successful allowed request in structured audit trail.
	if mcp.IsMCP {
		s.logAuditWithMCP(start, user, tenantID, domain, r.Method, "allowed", "", status, violations, mcp, protocol)
	} else {
		s.logAudit(start, user, tenantID, domain, r.Method, "allowed", "", status, violations)
	}
}

// loadBlockPageTemplate reads the coaching block page from disk.
func loadBlockPageTemplate(l *zap.SugaredLogger) (string, error) {
	l.Debug(utils.GetFunctionName())

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("unable to resolve caller path")
	}
	templatePath := filepath.Join(filepath.Dir(thisFile), "..", "html_templates", "block.html")
	b, err := os.ReadFile(templatePath)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// renderBlockPage injects denial reason into loaded template.
func (s *Server) renderBlockPage(reason string) string {
	s.Logger.Debug(utils.GetFunctionName())

	safeReason := html.EscapeString(reason)
	if s.BlockPage != "" {
		// Support template files using printf-style %s placeholder.
		if strings.Contains(s.BlockPage, "%s") {
			return fmt.Sprintf(s.BlockPage, safeReason)
		}
		return s.BlockPage
	}
	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Access Blocked</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.5; margin: 2rem;">
  <h1>Access Blocked as per policy</h1>
  <p>Your request could not be completed because it violates the current security policy.</p>
  <p><strong>Details:</strong> %s</p>
</body>
</html>`, safeReason)
}

// evaluate executes identity, policy, and request DLP checks.
func (s *Server) evaluate(r *http.Request, mcp MCPRequest, protocol, version string) (user, tenantID, domain string, blocked bool, status int, reason string, viol []inspector.Violation) {
	domain = targetDomain(r)
	version = mcp.Version

	id, err := s.Auth.ExtractAuthorizationnHeader(r)
	if err != nil {
		s.Logger.Debug("JWT extraction failed: ", err)
		s.Logger.Debug("Authorization header present: ", r.Header.Get("Authorization") != "")
		if errors.Is(err, auth.ErrMissingTenant) || errors.Is(err, auth.ErrUnknownTenant) {
			return "", "", domain, true, http.StatusForbidden, err.Error(), nil
		}
	} else {
		user = id.User
		tenantID = id.TenantID
	}

	s.Logger.Debug("r.Host: ", r.Host, ", Domain: ", domain, ", User: ", user, ", TenantID: ", tenantID, ", Protocol: ", protocol, ", Version: ", version)

	action, message := s.Policy.Decide(domain, r.Method)
	if action == policy.ActionBlock {
		return user, tenantID, domain, true, http.StatusForbidden, message, nil
	}

	s.Logger.Debug("DLP Inspection")
	viol, inspectedBytes, err := s.Inspector.InspectRequest(r)
	if err != nil {
		return user, tenantID, domain, true, http.StatusBadRequest, "inspection failed", nil
	}
	s.Metrics.RecordRequestBytesInspected(inspectedBytes)

	if len(viol) > 0 {
		s.Metrics.RecordDLPViolation()
		return user, tenantID, domain, true, http.StatusForbidden, "dlp violation", viol
	}
	return user, tenantID, domain, false, 0, "", nil
}

func (s *Server) FindProtocol(r *http.Request, mcp MCPRequest) string {
	var proto string
	// CONNECT requests indicate HTTPS tunnel establishment; subsequent requests in the tunnel will have r.TLS set
	isHTTPS := r.TLS != nil || strings.EqualFold(r.Method, http.MethodConnect)

	if !mcp.IsMCP {
		s.Logger.Debug("Not MCP Packet")
		if isHTTPS {
			s.Logger.Debug("HTTPS")
			proto = "HTTPS"
		} else {
			s.Logger.Debug("HTTP")
			proto = "HTTP"
		}
	} else {
		if isHTTPS {
			s.Logger.Debug("HTTPS+MCP")
			proto = "HTTPS+MCP"
		} else {
			s.Logger.Debug("HTTP+MCP")
			proto = "HTTP+MCP"
		}
	}
	return proto
}

func targetDomain(r *http.Request) string {
	if r.URL != nil && r.URL.Host != "" {
		// Prefer URL host when available because it reflects full target URI.
		return stripPort(r.URL.Host)
	}
	return stripPort(r.Host)
}

// cloneRequest creates a shallow request copy for safe forwarding mutations.
//
// Inputs:
// - r: source request.
//
// Outputs:
// - Cloned request preserving original context/body reference.
//
// Side effects:
// - None.
//
// Assumptions:
// - Body was already normalized by caller when needed.
func cloneRequest(r *http.Request) *http.Request {
	// Clone request metadata and context for outbound transport usage.
	cp := r.Clone(r.Context())
	if r.Body != nil {
		// Preserve body stream reference for transport to consume.
		cp.Body = r.Body
	}
	return cp
}

// logAudit emits a structured JSON audit record.
//
// Inputs:
// - start: request start time for latency computation.
// - user/domain/method/action/reason/code/violations: decision context.
//
// Outputs:
// - None.
//
// Side effects:
// - Writes JSON event to configured logger output sink.
func (s *Server) logAudit(start time.Time, user, tenantID, domain, method, action, reason string, code int, violations []inspector.Violation) {
	file, fn, line := callerInfo()
	entry := AuditLog{
		Time:       time.Now().UTC(),
		User:       user,
		TenantID:   tenantID,
		Domain:     domain,
		Method:     method,
		Action:     action,
		Reason:     reason,
		LatencyMS:  time.Since(start).Milliseconds(),
		StatusCode: code,
		Violations: violations,
		SourceFile: file,
		SourceFunc: fn,
		SourceLine: line,
	}
	// Emit structured audit event with source metadata for traceability.
	s.Logger.Info("audit_event", "audit", entry)
}

// logAuditWithMCP emits a structured JSON audit record with MCP protocol information.
//
// Inputs:
// - start: request start time for latency computation.
// - user/domain/method/action/reason/code/violations: decision context.
// - mcp: MCP protocol information
// - protocol: protocol name (HTTP, HTTPS, MCP)
//
// Outputs:
// - None.
//
// Side effects:
// - Writes JSON event to configured logger output sink with MCP metadata.
func (s *Server) logAuditWithMCP(start time.Time, user, tenantID, domain, method, action, reason string, code int, violations []inspector.Violation, mcp MCPRequest, protocol string) {
	file, fn, line := callerInfo()
	entry := AuditLog{
		Time:       time.Now().UTC(),
		User:       user,
		TenantID:   tenantID,
		Domain:     domain,
		Method:     method,
		Action:     action,
		Reason:     reason,
		LatencyMS:  time.Since(start).Milliseconds(),
		StatusCode: code,
		Violations: violations,
		SourceFile: file,
		SourceFunc: fn,
		SourceLine: line,
		Protocol:   protocol,
		AgentID:    mcp.AgentID,
		SessionID:  mcp.SessionID,
		TraceID:    mcp.TraceID,
	}
	// Emit structured audit event with source metadata and MCP information for traceability.
	s.Logger.Info("audit_event", "audit", entry)
}

// callerInfo returns caller file, function, and line for log correlation.
func callerInfo() (string, string, int) {
	pc, file, line, ok := runtime.Caller(2)
	if !ok {
		return "", "", 0
	}
	fn := runtime.FuncForPC(pc)
	funcName := ""
	if fn != nil {
		funcName = fn.Name()
	}
	return filepath.Base(file), funcName, line
}

// writeSimpleHTTPResponse writes minimal plain-text HTTP response on buffered writer.
//
// Inputs:
// - bw: buffered writer bound to client tunnel.
// - code: HTTP status code.
// - msg: response body message.
//
// Outputs:
// - None.
//
// Side effects:
// - Writes status line, headers, and body bytes to downstream buffer.
func writeSimpleHTTPResponse(bw *bufio.Writer, code int, msg string) {
	// Compose status line with canonical status text.
	status := fmt.Sprintf("HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
	// Build plain-text response body from provided message.
	body := msg + "\n"
	// Write status line first per HTTP response format.
	_, _ = bw.WriteString(status)
	// Write content length header so client can delimit response body.
	_, _ = bw.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	// Write minimal content-type and connection headers.
	_, _ = bw.WriteString("Content-Type: text/plain\r\nConnection: keep-alive\r\n\r\n")
	// Write response payload bytes.
	_, _ = bw.WriteString(body)
}
