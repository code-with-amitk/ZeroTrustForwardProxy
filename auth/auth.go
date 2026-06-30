// Package auth provides identity extraction and validation primitives.
//
// Architecture fit:
//   - Proxy request handling depends on this package to resolve request identity
//     before policy evaluation.
//
// Key responsibilities:
// - Define the validator interface used by proxy runtime.
// - Extract bearer tokens from HTTP headers.
// - Validate tokens and resolve numeric tenant_id for multi-tenant policy routing.
//
// Design decisions:
//   - Validation is interface-based so real JWT/JWKS verification can replace
//     mock behavior without changing proxy orchestration.
//   - tenant_mode strict requires tenant_id in JWT; dev falls back to default_tenant_id.
package auth

import (
	"errors"
	"net/http"
	"strings"
	"zerotrust-forward-proxy/config"
	"zerotrust-forward-proxy/jwt"
	"zerotrust-forward-proxy/utils"

	"go.uber.org/zap"
)

var ErrMissingToken = errors.New("missing bearer token")

// Identity describes the authenticated principal associated with a request.
type Identity struct {
	User     string
	TenantID int64
	Raw      string
}

type Validator interface {
	ExtractAuthorizationnHeader(r *http.Request) (Identity, error)
}

// JWTValidator validates bearer JWTs and resolves tenant_id per config.TenantMode.
type JWTValidator struct {
	logger          *zap.SugaredLogger
	tenantMode      string
	defaultTenantID int64
	policyDir       string
}

// NewJWTValidator constructs a validator using tenancy settings from cfg.
func NewJWTValidator(logger *zap.SugaredLogger, cfg config.Config) JWTValidator {
	return JWTValidator{
		logger:          logger,
		tenantMode:      cfg.TenantMode,
		defaultTenantID: cfg.DefaultTenantID,
		policyDir:       cfg.PolicyDir,
	}
}

// NewMockJWTValidator preserves the old constructor name for tests and local dev.
func NewMockJWTValidator(logger *zap.SugaredLogger) JWTValidator {
	return NewJWTValidator(logger, config.Default())
}

// ExtractAuthorizationnHeader validates the bearer token and resolves tenant_id.
func (v JWTValidator) ExtractAuthorizationnHeader(r *http.Request) (Identity, error) {
	if v.logger != nil {
		v.logger.Debug(utils.GetFunctionName())
	}

	h := r.Header.Get("Authorization")
	if h == "" {
		h = r.Header.Get("Proxy-Authorization")
	}
	if h == "" {
		return Identity{}, ErrMissingToken
	}

	if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return Identity{}, ErrMissingToken
	}

	token := strings.TrimSpace(h[7:])
	if token == "" {
		return Identity{}, ErrMissingToken
	}

	claims, err := jwt.ValidateJWT(v.logger, token)
	if err != nil {
		return Identity{}, err
	}

	user := claims.User
	if user == "" {
		user = "anonymous"
	}

	tenantID, err := v.resolveTenantID(claims.TenantID)
	if err != nil {
		return Identity{}, err
	}

	return Identity{User: user, TenantID: tenantID, Raw: token}, nil
}

func (v JWTValidator) resolveTenantID(claim int64) (int64, error) {
	if claim > 0 {
		if v.tenantMode == "strict" && !TenantPolicyExists(v.policyDir, claim) {
			return 0, ErrUnknownTenant
		}
		return claim, nil
	}

	if v.tenantMode == "strict" {
		return 0, ErrMissingTenant
	}

	if v.defaultTenantID > 0 {
		return v.defaultTenantID, nil
	}
	return 0, ErrMissingTenant
}
