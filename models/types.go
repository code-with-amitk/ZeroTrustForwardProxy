package models

import (
	"crypto/rsa"
	"crypto/x509"
	"net/http"
	"sync"
	"zerotrust-forward-proxy/auth"
	"zerotrust-forward-proxy/config"
	"zerotrust-forward-proxy/inspector"
	"zerotrust-forward-proxy/metrics"
	"zerotrust-forward-proxy/policy"

	"go.uber.org/zap"
)

// ////////////// JWT ////////////////////
/*
type JWTClaim struct {
	User                 string `json:"user"`      // User name of person having token
	TenantID             int64  `json:"tenant_id"` // Use PascalCase for export
	jwt.RegisteredClaims        // Embed standard claims
}
*/

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

/*
// Identity describes the authenticated principal associated with a request.
type Identity struct {
	User string
	Raw  string
}

type Validator interface {
	ExtractAuthorizationnHeader(r *http.Request) (Identity, error)
}

type MockJWTValidator struct {
	Logger *zap.SugaredLogger
}
*/
