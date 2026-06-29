package jwt

import (
	"testing"
)

func TestGenerateAndValidateTenantID(t *testing.T) {
	token, err := GenerateJWT(nil, "alice", "acme")
	if err != nil {
		t.Fatal(err)
	}

	claims, err := ValidateJWT(nil, token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.User != "alice" {
		t.Fatalf("user: got %q want alice", claims.User)
	}
	if claims.TenantID != "acme" {
		t.Fatalf("tenant_id: got %q want acme", claims.TenantID)
	}
}

func TestValidateJWTMissingTenantID(t *testing.T) {
	token, err := GenerateJWT(nil, "alice", "")
	if err != nil {
		t.Fatal(err)
	}

	claims, err := ValidateJWT(nil, token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.TenantID != "" {
		t.Fatalf("expected empty tenant_id, got %q", claims.TenantID)
	}
}
