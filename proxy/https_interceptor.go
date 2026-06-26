package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
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

	// Hijack Client Connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) // Client CONNECT Request Acknowledged

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
	defer s.Metrics.Observe(start, blocked, user, domain)

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

	// Peek ClientHello to extract SNI before issuing host cert to avoid unnecessary issuance.
	brRaw := bufio.NewReader(clientConn)
	sni, err := peekClientHelloSNI(brRaw)
	if err != nil {
		s.Logger.Debug("failed to parse ClientHello SNI, falling back to request host: ", err)
		sni = stripPort(r.Host)
	}

	// Re-evaluate policy using SNI-derived host to catch host-specific block rules.
	hostEvalReq := *r
	if sni != "" {
		hostEvalReq.Host = sni
	} else {
		hostEvalReq.Host = stripPort(r.Host)
	}
	_, domainAfterSNI, blockedAfterSNI, _, reasonAfterSNI, violAfterSNI := s.evaluate(&hostEvalReq, mcp, protocol, mcpVersion)
	if blockedAfterSNI {
		// Audit and close connection; client already received 200 so just close raw socket.
		if mcp.IsMCP {
			s.logAuditWithMCP(start, user, domainAfterSNI, r.Method, "blocked", reasonAfterSNI, http.StatusForbidden, violAfterSNI, mcp, "HTTPS+MCP")
		} else {
			s.logAudit(start, user, domainAfterSNI, r.Method, "blocked", reasonAfterSNI, http.StatusForbidden, violAfterSNI)
		}
		_ = clientConn.Close()
		return
	}

	// Build MITM TLS config with a certificate callback that reuses cached certs.
	certHost := stripPort(r.Host)
	if sni != "" {
		certHost = sni
	}
	bconn := &bufferedConn{Conn: clientConn, r: brRaw}
	tlsConn := tls.Server(bconn, s.newMITMTLSConfig(certHost))
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
		viol, inspectedBytes, err := s.Inspector.InspectRequest(req)
		if err != nil {
			// Reply inside tunnel with bad request when inspection fails.
			writeSimpleHTTPResponse(bw, http.StatusBadRequest, "inspection failed")
			// Flush buffered response bytes to client.
			_ = bw.Flush()
			continue
		}
		s.Metrics.RecordRequestBytesInspected(inspectedBytes)
		if len(viol) > 0 {
			// Block request inside tunnel when sensitive data is detected.
			writeSimpleHTTPResponse(bw, http.StatusForbidden, "dlp violation")
			// Flush blocked response bytes to client.
			_ = bw.Flush()
			// Record blocked metric event for this tunneled request.
			s.Metrics.Observe(start, true, user, domain)
			s.Metrics.RecordDLPViolation()
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
		respViol, inspectedBytes, err := s.Inspector.InspectResponse(resp)
		if err != nil {
			// Close upstream body and report inspection failure.
			_ = resp.Body.Close()
			writeSimpleHTTPResponse(bw, http.StatusBadGateway, "response inspection failed")
			// Flush failure response bytes.
			_ = bw.Flush()
			continue
		}
		s.Metrics.RecordResponseBytesInspected(inspectedBytes)
		if len(respViol) > 0 {
			// Close upstream body before replacing response with block decision.
			_ = resp.Body.Close()
			// Block tunneled response when DLP finds sensitive content.
			writeSimpleHTTPResponse(bw, http.StatusForbidden, "dlp violation in response")
			// Flush block response bytes.
			_ = bw.Flush()
			// Record blocked metric event for response-side DLP.
			s.Metrics.Observe(start, true, user, domain)
			s.Metrics.RecordDLPViolation()
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

// bufferedConn wraps a net.Conn and a bufio.Reader that may already contain
// data read from the connection (e.g., via Peek). Read will consume from the
// buffered reader first so that subsequent TLS reads see the same bytes.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

// peekClientHelloSNI attempts to parse the TLS ClientHello from the buffered
// reader and extract the SNI (server_name) if present. It uses Peek so bytes
// remain available for later reads.
func peekClientHelloSNI(br *bufio.Reader) (string, error) {
	// TLS record header is 5 bytes
	hdr, err := br.Peek(5)
	if err != nil {
		return "", err
	}
	// ContentType: 22 (handshake)
	if hdr[0] != 0x16 {
		return "", errors.New("not a TLS handshake record")
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	total := 5 + recLen
	buf, err := br.Peek(total)
	if err != nil {
		return "", err
	}
	// Handshake message starts at position 5
	if len(buf) < 9 {
		return "", errors.New("clienthello too short")
	}
	hsType := buf[5]
	if hsType != 0x01 { // client hello
		return "", errors.New("not client hello")
	}
	// Handshake length (3 bytes) at buf[6:9]
	hsLen := int(buf[6])<<16 | int(buf[7])<<8 | int(buf[8])
	if 9+hsLen > len(buf) {
		return "", errors.New("handshake length truncated")
	}
	// offset points to start of ClientHello body
	offset := 9
	// client_version (2) + random (32)
	if offset+34 > len(buf) {
		return "", errors.New("clienthello truncated at random")
	}
	offset += 34
	// session id
	if offset+1 > len(buf) {
		return "", errors.New("clienthello truncated at session id len")
	}
	sidLen := int(buf[offset])
	offset += 1
	if offset+sidLen > len(buf) {
		return "", errors.New("clienthello truncated at session id")
	}
	offset += sidLen
	// cipher suites
	if offset+2 > len(buf) {
		return "", errors.New("clienthello truncated at cipher suites len")
	}
	csLen := int(binary.BigEndian.Uint16(buf[offset : offset+2]))
	offset += 2
	if offset+csLen > len(buf) {
		return "", errors.New("clienthello truncated at cipher suites")
	}
	offset += csLen
	// compression methods
	if offset+1 > len(buf) {
		return "", errors.New("clienthello truncated at comp methods len")
	}
	compLen := int(buf[offset])
	offset += 1
	if offset+compLen > len(buf) {
		return "", errors.New("clienthello truncated at comp methods")
	}
	offset += compLen
	// If no extensions, return
	if offset+2 > len(buf) {
		return "", nil
	}
	extLen := int(binary.BigEndian.Uint16(buf[offset : offset+2]))
	offset += 2
	if offset+extLen > len(buf) {
		return "", errors.New("clienthello truncated at extensions")
	}
	endExt := offset + extLen
	for offset+4 <= endExt {
		if offset+4 > len(buf) {
			break
		}
		extType := binary.BigEndian.Uint16(buf[offset : offset+2])
		el := int(binary.BigEndian.Uint16(buf[offset+2 : offset+4]))
		offset += 4
		if offset+el > len(buf) {
			break
		}
		if extType == 0x0000 { // server_name
			if el < 2 || offset+2 > len(buf) {
				return "", nil
			}
			pos := offset + 2
			endNames := offset + el
			for pos+3 <= endNames {
				nameType := buf[pos]
				nameLen := int(binary.BigEndian.Uint16(buf[pos+1 : pos+3]))
				pos += 3
				if pos+nameLen > endNames {
					break
				}
				if nameType == 0 {
					return string(buf[pos : pos+nameLen]), nil
				}
				pos += nameLen
			}
			return "", nil
		}
		offset += el
	}
	return "", nil
}
