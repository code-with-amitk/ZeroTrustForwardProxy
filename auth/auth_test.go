// Package auth tests identity extraction and token validation behavior.
//
// Architecture fit:
// - Verifies the auth layer contract used by proxy request evaluation.
//
// Key responsibilities:
// - Assert mock JWT parser resolves user from expected token format.
package auth

import (
	"net/http"
	"testing"
)

// TestExtractAuthorizationnHeader verifies that a valid mock bearer token maps to user identity.
//
// Inputs:
// - Synthetic HTTP request with Authorization header.
//
// Outputs:
// - Test pass/fail based on extracted user.
//
// Side effects:
// - None.
func TestExtractAuthorizationnHeader(t *testing.T) {
	// Create validator instance under test.
	v := MockJWTValidator{}
	// Construct request carrying Authorization header consumed by validator.
	r, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	// Inject mock-valid token that should resolve to user "alice".
	r.Header.Set("Authorization", "Bearer valid:alice")
	// Execute extraction/validation logic to recover identity.
	id, err := v.ExtractAuthorizationnHeader(r)
	if err != nil {
		t.Fatal(err)
	}
	// Assert identity user was derived from token payload.
	if id.User != "alice" {
		t.Fatalf("expected alice, got %s", id.User)
	}
}
