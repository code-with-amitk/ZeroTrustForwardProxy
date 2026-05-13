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
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
}

// Server orchestrates proxy request handling and security enforcement.
type Server struct {
	Cfg       config.Config
	Ca        *CertificateAuthority
	Auth      auth.Validator
	Policy    *policy.Engine
	Inspector *inspector.Inspector
	Metrics   *metrics.Collector
	Logger    *zap.SugaredLogger
	Transport *http.Transport
	BlockPage string
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

	return &Server{
		Cfg:       cfg,
		Ca:        ca,
		Auth:      authz,
		Policy:    pe,
		Inspector: dlp,
		Metrics:   m,
		Logger:    l,
		Transport: tr,
		BlockPage: blockPage,
	}
}

// Start proxy server and start serving requests.
func (s *Server) Start() error {
	srv := &http.Server{
		Addr:              s.Cfg.ListenAddr,
		Handler:           s, //Plugging your Server into the standard library here
		ReadHeaderTimeout: 10 * time.Second,
	}

	// ListenAndServe() calls ServeHTTP()
	// listen(port=8080)
	// accept() //wait for incoming connections
	// spawn a new goroutine when connection arrive.
	// When connection arrive, goroutine parse and store in http.Request
	// call = srv.Handler.ServeHTTP(w, r)
	return srv.ListenAndServe()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.Logger.Debug("ServeHTTP()")
	s.Logger.Debug("r.Method: ", r.Method)

	// Route CONNECT requests into explicit TLS interception path.
	if strings.EqualFold(r.Method, http.MethodConnect) {
		s.handleHTTPS(w, r)
		return
	}
	// Handle regular HTTP requests through standard forwarding path.
	s.handleHTTP(w, r)
}

// HTTP Request
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	s.Logger.Debug("handleHTTP()")

	start := time.Now()

	// Policy Application, DLP Inspection
	user, domain, blocked, status, reason, violations := s.evaluate(r)
	s.Logger.Debug("user: ", user, ", Domain: ", domain, ", blocked: ", blocked, ", status: ", status, ", reason: ", reason, ", violations: ", violations)

	// Metrics Emission
	defer s.Metrics.Observe(start, blocked)
	if blocked {
		// Return a coaching HTML page for policy/DLP denials.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(s.renderBlockPage(reason)))

		s.logAudit(start, user, domain, r.Method, "blocked", reason, http.StatusForbidden, violations)
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
		s.logAudit(start, user, domain, r.Method, "blocked", err.Error(), http.StatusBadGateway, violations)
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
	s.logAudit(start, user, domain, r.Method, "allowed", "", status, violations)
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

// Perform HTTPS interception for CONNECT tunnels.
func (s *Server) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	s.Logger.Debug(utils.GetFunctionName())

	// Capture tunnel start time for latency and event accounting.
	start := time.Now()

	s.Logger.Debug("request: ", r)
	// Apply identity/policy/request DLP checks on initial CONNECT metadata.
	user, domain, blocked, _, reason, violations := s.evaluate(r)

	// Emit per-CONNECT metrics when this handler exits.
	defer s.Metrics.Observe(start, blocked)

	if blocked {
		// Deny CONNECT early if controls fail before tunnel setup.
		http.Error(w, reason, http.StatusForbidden)
		// Audit denied CONNECT attempt.
		s.logAudit(start, user, domain, r.Method, "blocked", reason, http.StatusForbidden, violations)
		return
	}

	// Acquire connection hijacker to take over raw socket for TLS MITM.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	// Hijack client TCP connection from net/http server.
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}

	// Confirm tunnel establishment before upgrading to intercepted TLS session.
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Issue (or fetch cached) host certificate signed by local root CA.
	issued, err := s.Ca.IssueForHost(r.Host)
	if err != nil {
		// Close raw socket when cert issuance fails.
		_ = clientConn.Close()
		return
	}
	// Build tls.Certificate pair consumed by tls.Server.
	pair, err := tls.X509KeyPair(issued.CertPEM, issued.KeyPEM)
	if err != nil {
		// Close raw socket when cert material is invalid.
		_ = clientConn.Close()
		return
	}
	// Wrap client connection with TLS server endpoint for MITM decryption.
	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
	})
	// Complete TLS handshake with client before reading decrypted HTTP requests.
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		return
	}

	// Build buffered reader/writer over tunneled TLS socket for request loop.
	br := bufio.NewReader(tlsConn)
	bw := bufio.NewWriter(tlsConn)
	for {
		// Read one decrypted HTTP request from intercepted TLS stream.
		req, err := http.ReadRequest(br)
		if err != nil {
			// Ignore EOF as normal tunnel close; audit other read failures.
			if !errors.Is(err, io.EOF) {
				s.logAudit(start, user, domain, r.Method, "blocked", err.Error(), http.StatusBadGateway, nil)
			}
			// Close TLS tunnel when request loop terminates.
			_ = tlsConn.Close()
			return
		}
		// Rebuild upstream URL metadata for outbound HTTPS RoundTrip.
		req.URL.Scheme = "https"
		req.URL.Host = r.Host
		req.RequestURI = ""

		// Inspect decrypted request payload for DLP violations before egress.
		viol, err := s.Inspector.InspectRequest(req)
		if err != nil {
			// Reply inside tunnel with bad request when inspection fails.
			writeSimpleHTTPResponse(bw, http.StatusBadRequest, "inspection failed")
			// Flush buffered response bytes to client.
			_ = bw.Flush()
			continue
		}
		if len(viol) > 0 {
			// Block request inside tunnel when sensitive data is detected.
			writeSimpleHTTPResponse(bw, http.StatusForbidden, "dlp violation")
			// Flush blocked response bytes to client.
			_ = bw.Flush()
			// Record blocked metric event for this tunneled request.
			s.Metrics.Observe(start, true)
			// Audit DLP enforcement event with violation details.
			s.logAudit(start, user, domain, req.Method, "blocked", "dlp violation", http.StatusForbidden, viol)
			continue
		}

		// Forward decrypted request to real upstream over HTTPS.
		resp, err := s.Transport.RoundTrip(req)
		if err != nil {
			// Surface upstream failure to client inside existing tunnel.
			writeSimpleHTTPResponse(bw, http.StatusBadGateway, err.Error())
			// Flush error response bytes.
			_ = bw.Flush()
			continue
		}

		// Inspect upstream response payload before returning to client.
		respViol, err := s.Inspector.InspectResponse(resp)
		if err != nil {
			// Close upstream body and report inspection failure.
			_ = resp.Body.Close()
			writeSimpleHTTPResponse(bw, http.StatusBadGateway, "response inspection failed")
			// Flush failure response bytes.
			_ = bw.Flush()
			continue
		}
		if len(respViol) > 0 {
			// Close upstream body before replacing response with block decision.
			_ = resp.Body.Close()
			// Block tunneled response when DLP finds sensitive content.
			writeSimpleHTTPResponse(bw, http.StatusForbidden, "dlp violation in response")
			// Flush block response bytes.
			_ = bw.Flush()
			// Record blocked metric event for response-side DLP.
			s.Metrics.Observe(start, true)
			// Audit response DLP violation.
			s.logAudit(start, user, domain, req.Method, "blocked", "dlp response violation", http.StatusForbidden, respViol)
			continue
		}

		// Write full upstream response (status, headers, body) into TLS tunnel.
		if err := resp.Write(bw); err != nil {
			// Close resources on downstream write failure.
			_ = resp.Body.Close()
			_ = tlsConn.Close()
			return
		}
		// Flush buffered response bytes to ensure client receives payload promptly.
		_ = bw.Flush()
		// Release upstream response body resources after write completion.
		_ = resp.Body.Close()
		// Audit successful tunneled request.
		s.logAudit(start, user, domain, req.Method, "allowed", "", resp.StatusCode, nil)
	}
}

// evaluate executes identity, policy, and request DLP checks.
func (s *Server) evaluate(r *http.Request) (user, domain string, blocked bool, status int, reason string, viol []inspector.Violation) {
	s.Logger.Debug(utils.GetFunctionName())

	// Resolve identity from Authorization header via configured validator.
	id, err := s.Auth.ExtractAuthorizationnHeader(r)
	if err == nil {
		user = id.User
	} else {
		// Log the extraction error to help debug auth failures
		s.Logger.Debug("JWT extraction failed: ", err)
		// Log headers for debugging
		s.Logger.Debug("Authorization header present: ", r.Header.Get("Authorization") != "")
	}

	// Determine target domain used for policy checks and logging.
	domain = targetDomain(r)
	s.Logger.Debug("r.Host: ", r.Host, ", Domain: ", domain, ", User: ", user)

	// Check Policy Decision
	if s.Policy.Decide(user, domain) == policy.Block {
		return user, domain, true, http.StatusForbidden, "policy blocked request", nil
	}

	// DLP Inspection
	s.Logger.Debug("DLP Inspection")
	viol, err = s.Inspector.InspectRequest(r)
	if err != nil {
		return user, domain, true, http.StatusBadRequest, "inspection failed", nil
	}

	// Block request when DLP signatures are detected.
	if len(viol) > 0 {
		return user, domain, true, http.StatusForbidden, "dlp violation", viol
	}
	return user, domain, false, 0, "", nil
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
func (s *Server) logAudit(start time.Time, user, domain, method, action, reason string, code int, violations []inspector.Violation) {
	file, fn, line := callerInfo()
	// Build in-memory audit document from decision metadata.
	entry := AuditLog{
		Time:       time.Now().UTC(),
		User:       user,
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
