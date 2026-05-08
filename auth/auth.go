// Package auth provides identity extraction and validation primitives.
//
// Architecture fit:
//   - Proxy request handling depends on this package to resolve request identity
//     before policy evaluation.
//
// Key responsibilities:
// - Define the validator interface used by proxy runtime.
// - Extract bearer tokens from HTTP headers.
// - Validate tokens (mock implementation in this codebase).
//
// Design decisions:
//   - Validation is interface-based so real JWT/JWKS verification can replace
//     mock behavior without changing proxy orchestration.
package auth

import (
	"errors"
	"net/http"
	"strings"
	"zerotrust-forward-proxy/jwt"
	"zerotrust-forward-proxy/utils"

	"go.uber.org/zap"
)

var ErrMissingToken = errors.New("missing bearer token")

// Identity describes the authenticated principal associated with a request.

type Identity struct {
	User string
	Raw  string
}

type Validator interface {
	ExtractAuthorizationnHeader(r *http.Request) (Identity, error)
}

type MockJWTValidator struct {
	logger *zap.SugaredLogger
}

func NewMockJWTValidator(logger *zap.SugaredLogger) MockJWTValidator {
	return MockJWTValidator{logger: logger}
}

// Extract Authorization header
func (v MockJWTValidator) ExtractAuthorizationnHeader(r *http.Request) (Identity, error) {
	utils.GetFunctionName()

	// Read Authorization header where bearer token is expected.
	h := r.Header.Get("Authorization")
	if h == "" {
		return Identity{}, ErrMissingToken
	}
	v.logger.Debug("authorization header: ", h)

	// Normalize casing to accept "Bearer" or mixed-case prefix variants.
	if !strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return Identity{}, ErrMissingToken
	}

	// Remove prefix and trim whitespace to isolate raw token value.
	token := strings.TrimSpace(h[7:])
	if token == "" {
		return Identity{}, ErrMissingToken
	}
	v.logger.Debug("JWT token: ", token)

	// Validate JWT Token & extract username from it
	claims, err := jwt.ValidateJWT(v.logger, token)
	if err != nil {
		return Identity{}, err
	}

	v.logger.Debug("JWT claims: ", claims)
	v.logger.Debug("User from JWT: ", claims.User)

	if claims.User != "" {
		return Identity{User: claims.User, Raw: token}, nil
	}
	return Identity{User: "anonymous", Raw: token}, nil
}
