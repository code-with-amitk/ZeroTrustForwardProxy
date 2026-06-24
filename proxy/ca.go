// Package proxy contains core transport/runtime components for the forward proxy.
//
// This file focuses on certificate authority management used by HTTPS MITM.
//
// Architecture fit:
// - CONNECT interception requires domain-specific leaf certificates.
// - This module owns root CA loading/creation and leaf issuance.
//
// Key responsibilities:
// - Load persisted root CA from disk or create a new one.
// - Issue per-host server certificates signed by root CA.
// - Cache generated leaf certs to reduce CPU under repeated domains.
//
// Design decisions:
// - Root CA key material is stored as PEM files with restrictive permissions.
// - Leaf certs are cached in memory behind RWMutex for concurrency safety.
package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
	"zerotrust-forward-proxy/utils"
)

/*
// CertificateAuthority holds root signing material and issued leaf cache.
type CertificateAuthority struct {
	cert    *x509.Certificate
	key     *rsa.PrivateKey
	baseTLS *TLSMaterial
	cache   map[string]*TLSMaterial
	mu      sync.RWMutex
}

// TLSMaterial is PEM-encoded certificate/private-key pair.
type TLSMaterial struct {
	CertPEM []byte
	KeyPEM  []byte
}
*/

// CertificateAuthority holds root signing material and issued leaf cache.
type CertificateAuthority struct {
	Cert    *x509.Certificate
	Key     *rsa.PrivateKey
	BaseTLS *TLSMaterial
	Cache   map[string]*TLSMaterial
	Mu      sync.RWMutex
}

// TLSMaterial is PEM-encoded certificate/private-key pair.
type TLSMaterial struct {
	CertPEM []byte
	KeyPEM  []byte
}

// Load crt,key file. Create new crt,key if files does not exist
func LoadOrCreateCA(certFile, keyFile string) (*CertificateAuthority, error) {
	utils.GetFunctionName()

	if _, err := os.Stat(certFile); err == nil {
		// if crt, key are present
		return loadCA(certFile, keyFile)
	}
	// crt, key not present
	return createCA(certFile, keyFile)
}

// loadCA parses existing PEM files into signing material.
//
// Inputs:
// - certFile/keyFile: CA PEM paths.
//
// Outputs:
// - CertificateAuthority with empty leaf cache.
// - error for invalid files or parse failure.
//
// Side effects:
// - Reads certificate and key from disk.
func loadCA(certFile, keyFile string) (*CertificateAuthority, error) {
	// Read CA certificate PEM bytes.
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	// Read CA private key PEM bytes.
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	// Decode certificate and key PEM blocks prior to DER parsing.
	cBlock, _ := pem.Decode(certPEM)
	kBlock, _ := pem.Decode(keyPEM)
	if cBlock == nil || kBlock == nil {
		return nil, errors.New("invalid CA cert/key PEM")
	}
	// Parse X.509 certificate to obtain issuer metadata for signing.
	cert, err := x509.ParseCertificate(cBlock.Bytes)
	if err != nil {
		return nil, err
	}
	// Parse RSA private key used to sign leaf certificates.
	key, err := x509.ParsePKCS1PrivateKey(kBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return &CertificateAuthority{
		Cert:    cert,
		Key:     key,
		BaseTLS: &TLSMaterial{CertPEM: certPEM, KeyPEM: keyPEM},
		Cache:   map[string]*TLSMaterial{},
	}, nil
}

// Create cert, key using crypto package in go
func createCA(certFile, keyFile string) (*CertificateAuthority, error) {
	// Create RSA key size = 4096
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	// Generate random serial number
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}

	// Cert struct for certificate generation
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "ZeroTrust Forward Proxy Root CA",
			Organization: []string{"ZeroTrustForwardProxy"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0), //10 year valid
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	// Create self signed root CA cert
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	// Write cert, key to files
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		return nil, err
	}
	// Parse generated DER into certificate struct used by issuer runtime.
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CertificateAuthority{
		Cert:    cert,
		Key:     key,
		BaseTLS: &TLSMaterial{CertPEM: certPEM, KeyPEM: keyPEM},
		Cache:   map[string]*TLSMaterial{},
	}, nil
}

// IssueForHost returns a leaf certificate signed by root CA for given host.
//
// Inputs:
// - host: DNS name or IP, optionally with port.
//
// Outputs:
// - TLSMaterial containing PEM cert/key pair.
// - error on signing failures.
//
// Side effects:
// - Mutates in-memory certificate cache.
// - Performs cryptographic key generation.
//
// Assumptions:
// - Caller passes host extracted from CONNECT target or request URL.
func (ca *CertificateAuthority) IssueForHost(host string) (*TLSMaterial, error) {
	// Normalize host by removing optional port segment.
	host = stripPort(host)
	// Read-lock cache for fast-path certificate reuse.
	ca.Mu.RLock()
	if m, ok := ca.Cache[host]; ok {
		ca.Mu.RUnlock()
		return m, nil
	}
	ca.Mu.RUnlock()

	// Generate per-host ECDSA P-256 keypair for leaf certificate.
	// P-256 key generation is ~50x faster than RSA 2048 (~0.05 ms vs ~3 ms),
	// directly reducing latency on cold-cache CONNECT tunnel setup.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	// Allocate random serial number for issued leaf certificate.
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}
	// Build server certificate template constrained to requested host.
	// KeyUsageKeyEncipherment is omitted — it is RSA-specific; ECDSA uses
	// key agreement (ECDH) for key exchange, not direct encipherment.
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{host},
	}
	// If target is an IP literal, issue certificate with IP SAN.
	if ip := net.ParseIP(host); ip != nil {
		tpl.IPAddresses = append(tpl.IPAddresses, ip)
		tpl.DNSNames = nil
	}
	// Sign leaf cert with root CA key (RSA). Signing a ECDSA public key with an
	// RSA CA is standard — the CA algorithm and leaf algorithm are independent.
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}
	// Marshal ECDSA private key to SEC 1 DER format (RFC 5915).
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	// Encode signed cert and EC key as PEM for tls.X509KeyPair consumption.
	mat := &TLSMaterial{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
	// Cache issued certificate for future requests to same host.
	ca.Mu.Lock()
	ca.Cache[host] = mat
	ca.Mu.Unlock()
	return mat, nil
}

// stripPort returns host without port if host:port format is provided.
//
// Inputs:
// - hostport: host or host:port string.
//
// Outputs:
// - Host component only.
//
// Side effects:
// - None.
//
// Assumptions:
// - If parsing fails, input did not include a valid port and is returned as-is.
func stripPort(hostport string) string {
	// Parse host and port components when present.
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return h
}
