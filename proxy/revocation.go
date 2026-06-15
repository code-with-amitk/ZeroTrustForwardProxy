package proxy

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

const (
	defaultRevocationTTL = 24 * time.Hour
	unknownRevocationTTL = 30 * time.Minute
)

type revocationStatus int

const (
	revocationUnknown revocationStatus = iota
	revocationGood
	revocationRevoked
)

type revocationEntry struct {
	status revocationStatus
	expiry time.Time
	reason string
}

func (s *Server) newUpstreamTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS12,
		VerifyConnection: s.verifyUpstreamConnection,
	}
}

func (s *Server) verifyUpstreamConnection(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("upstream TLS connection has no peer certificates")
	}

	leaf := cs.PeerCertificates[0]
	issuer := getIssuerCertificate(cs.PeerCertificates)
	fingerprint := fingerprintCert(leaf)

	if entry := s.getRevocationEntry(fingerprint); entry != nil {
		if time.Now().Before(entry.expiry) {
			if entry.status == revocationRevoked {
				return fmt.Errorf("upstream certificate revoked: %s", entry.reason)
			}
			return nil
		}
	}

	status, ttl, reason := evaluateConnectionRevocation(cs, leaf, issuer)
	s.cacheRevocationStatus(fingerprint, status, ttl, reason)

	if status == revocationRevoked {
		return fmt.Errorf("upstream certificate revoked: %s", reason)
	}

	if status == revocationUnknown && issuer != nil {
		go s.asyncRefreshRevocation(fingerprint, leaf, issuer)
	}

	return nil
}

func evaluateConnectionRevocation(cs tls.ConnectionState, leaf, issuer *x509.Certificate) (revocationStatus, time.Duration, string) {
	if issuer != nil && len(cs.OCSPResponse) > 0 {
		status, ttl, reason := parseOCSPResponse(cs.OCSPResponse, leaf, issuer)
		if status != revocationUnknown {
			return status, ttl, reason
		}
	}
	return revocationUnknown, unknownRevocationTTL, "no stapled OCSP or unknown status"
}

func parseOCSPResponse(raw []byte, leaf, issuer *x509.Certificate) (revocationStatus, time.Duration, string) {
	resp, err := ocsp.ParseResponse(raw, issuer)
	if err != nil {
		return revocationUnknown, unknownRevocationTTL, fmt.Sprintf("invalid stapled OCSP: %v", err)
	}

	if resp.Status == ocsp.Good {
		ttl := defaultRevocationTTL
		if !resp.NextUpdate.IsZero() {
			if next := resp.NextUpdate.Sub(time.Now()); next > 0 {
				ttl = next
			}
		}
		return revocationGood, ttl, "ocsp good"
	}

	if resp.Status == ocsp.Revoked {
		return revocationRevoked, defaultRevocationTTL, fmt.Sprintf("ocsp revoked at %s", resp.RevokedAt)
	}

	return revocationUnknown, unknownRevocationTTL, fmt.Sprintf("ocsp status %d", resp.Status)
}

func (s *Server) asyncRefreshRevocation(fingerprint string, leaf, issuer *x509.Certificate) {
	status, ttl, reason := fetchOCSPStatus(leaf, issuer)
	if status == revocationUnknown {
		crlStatus, crlTTL, crlReason := fetchCRLStatus(leaf, issuer)
		if crlStatus != revocationUnknown {
			status = crlStatus
			ttl = crlTTL
			reason = crlReason
		}
	}
	s.cacheRevocationStatus(fingerprint, status, ttl, reason)
}

func fetchOCSPStatus(leaf, issuer *x509.Certificate) (revocationStatus, time.Duration, string) {
	if len(leaf.OCSPServer) == 0 {
		return revocationUnknown, unknownRevocationTTL, "no ocsp responder"
	}

	reqBytes, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{})
	if err != nil {
		return revocationUnknown, unknownRevocationTTL, fmt.Sprintf("ocsp request creation failed: %v", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(leaf.OCSPServer[0], "application/ocsp-request", bytes.NewReader(reqBytes))
	if err != nil {
		return revocationUnknown, unknownRevocationTTL, fmt.Sprintf("ocsp fetch failed: %v", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return revocationUnknown, unknownRevocationTTL, fmt.Sprintf("ocsp response read failed: %v", err)
	}

	return parseOCSPResponse(respBytes, leaf, issuer)
}

func fetchCRLStatus(leaf, issuer *x509.Certificate) (revocationStatus, time.Duration, string) {
	if len(leaf.CRLDistributionPoints) == 0 {
		return revocationUnknown, unknownRevocationTTL, "no crl distribution points"
	}

	client := &http.Client{Timeout: 10 * time.Second}
	for _, url := range leaf.CRLDistributionPoints {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			continue
		}

		crl, err := x509.ParseCRL(body)
		if err != nil {
			continue
		}
		if err := issuer.CheckCRLSignature(crl); err != nil {
			continue
		}
		for _, revoked := range crl.TBSCertList.RevokedCertificates {
			if revoked.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
				return revocationRevoked, defaultRevocationTTL, fmt.Sprintf("crl revoked at %s", revoked.RevocationTime)
			}
		}
		return revocationGood, defaultRevocationTTL, "crl good"
	}
	return revocationUnknown, unknownRevocationTTL, "crl fetch failed"
}

func (s *Server) getRevocationEntry(fingerprint string) *revocationEntry {
	s.upstreamRevocationMu.RLock()
	entry, ok := s.upstreamRevocationCache[fingerprint]
	s.upstreamRevocationMu.RUnlock()
	if !ok {
		return nil
	}
	return entry
}

func (s *Server) cacheRevocationStatus(fingerprint string, status revocationStatus, ttl time.Duration, reason string) {
	s.upstreamRevocationMu.Lock()
	defer s.upstreamRevocationMu.Unlock()
	s.upstreamRevocationCache[fingerprint] = &revocationEntry{
		status: status,
		expiry: time.Now().Add(ttl),
		reason: reason,
	}
}

func fingerprintCert(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func getIssuerCertificate(chain []*x509.Certificate) *x509.Certificate {
	if len(chain) < 2 {
		return nil
	}
	return chain[1]
}
