package jwt

import "testing"

func TestGenerateAndValidateTenantID(t *testing.T) {
	const tenantID int64 = 2
	token, err := GenerateJWT(nil, "alice", tenantID)
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
	if claims.TenantID != tenantID {
		t.Fatalf("tenant_id: got %d want %d", claims.TenantID, tenantID)
	}
}

func TestValidateJWTMissingTenantID(t *testing.T) {
	token, err := GenerateJWT(nil, "alice", 0)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := ValidateJWT(nil, token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.TenantID != 0 {
		t.Fatalf("expected tenant_id 0, got %d", claims.TenantID)
	}
}
