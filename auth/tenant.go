package auth

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrMissingTenant = errors.New("missing tenant_id in token")
	ErrUnknownTenant = errors.New("unknown tenant")
)

// TenantPolicyDBPath returns the compiled policy DB path for a tenant.
func TenantPolicyDBPath(policyDir, tenantID string) string {
	return filepath.Join(policyDir, tenantID, "policy.db")
}

// TenantPolicyExists reports whether a compiled policy.db exists for the tenant.
func TenantPolicyExists(policyDir, tenantID string) bool {
	if strings.TrimSpace(policyDir) == "" || strings.TrimSpace(tenantID) == "" {
		return false
	}
	_, err := os.Stat(TenantPolicyDBPath(policyDir, tenantID))
	return err == nil
}
