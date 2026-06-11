package proxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"time"

	"zerotrust-forward-proxy/utils"
)

// Perform HTTPS interception for CONNECT tunnels.
func (s *Server) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	s.Logger.Info(utils.GetFunctionName())

	s.Logger.Debug(utils.DumpHttpRequest(r))

	// Capture tunnel start time for latency and event accounting.
	start := time.Now()

	// Extract MCP protocol information if present
	mcp := s.extractMCPInfo(r)

	protocol := s.FindProtocol(r, mcp)
	mcpVersion := mcp.Version

	if mcp.IsMCP {
		s.Logger.Debug("MCP Protocol: ", protocol, ", mcpVersion: ", mcpVersion)
	}

	// Apply identity/policy/request DLP checks on initial CONNECT metadata.
	user, domain, blocked, _, reason, violations := s.evaluate(r, mcp, protocol, mcpVersion)

	// Emit per-CONNECT metrics when this handler exits.
	defer s.Metrics.Observe(start, blocked)

	if blocked {
		// Deny CONNECT early if controls fail before tunnel setup.
		http.Error(w, reason, http.StatusForbidden)
		// Audit denied CONNECT attempt.
		if mcp.IsMCP {
			s.logAuditWithMCP(start, user, domain, r.Method, "blocked", reason, http.StatusForbidden, violations, mcp, protocol)
		} else {
			s.logAudit(start, user, domain, r.Method, "blocked", reason, http.StatusForbidden, violations)
		}
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
				if mcp.IsMCP {
					s.logAuditWithMCP(start, user, domain, r.Method, "blocked", err.Error(), http.StatusBadGateway, nil, mcp, "HTTPS+MCP")
				} else {
					s.logAudit(start, user, domain, r.Method, "blocked", err.Error(), http.StatusBadGateway, nil)
				}
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
			if mcp.IsMCP {
				s.logAuditWithMCP(start, user, domain, req.Method, "blocked", "dlp violation", http.StatusForbidden, viol, mcp, "HTTPS+MCP")
			} else {
				s.logAudit(start, user, domain, req.Method, "blocked", "dlp violation", http.StatusForbidden, viol)
			}
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
			if mcp.IsMCP {
				s.logAuditWithMCP(start, user, domain, req.Method, "blocked", "dlp response violation", http.StatusForbidden, respViol, mcp, "HTTPS+MCP")
			} else {
				s.logAudit(start, user, domain, req.Method, "blocked", "dlp response violation", http.StatusForbidden, respViol)
			}
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
		if mcp.IsMCP {
			s.logAuditWithMCP(start, user, domain, req.Method, "allowed", "", resp.StatusCode, nil, mcp, "HTTPS+MCP")
		} else {
			s.logAudit(start, user, domain, req.Method, "allowed", "", resp.StatusCode, nil)
		}
	}
}
