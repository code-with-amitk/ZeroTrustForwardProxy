package jwt

import (
	"context"
	"net/http"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

type contextKey int

const claimsContextKey contextKey = iota

// JWTClaim contains user identity and registered JWT fields.
type JWTClaim struct {
	User     string `json:"user"`
	TenantID string `json:"tenant_id"`
	jwtv5.RegisteredClaims
}

// ContextWithClaims attaches validated JWT claims to the request context.
func ContextWithClaims(ctx context.Context, claims *JWTClaim) context.Context {
	return context.WithValue(ctx, claimsContextKey, claims)
}

// ClaimsFromContext returns claims set by auth middleware, or nil.
func ClaimsFromContext(ctx context.Context) *JWTClaim {
	v := ctx.Value(claimsContextKey)
	if v == nil {
		return nil
	}
	c, _ := v.(*JWTClaim)
	return c
}

// ClaimsFromRequest is a shortcut for ClaimsFromContext(r.Context()).
func ClaimsFromRequest(r *http.Request) *JWTClaim {
	return ClaimsFromContext(r.Context())
}
