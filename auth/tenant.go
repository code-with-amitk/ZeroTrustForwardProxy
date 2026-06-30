package auth

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	ErrMissingTenant = errors.New("missing tenant_id in token")
	ErrUnknownTenant = errors.New("unknown tenant")
)

// TenantDirName returns the on-disk directory segment for a numeric tenant_id.
func TenantDirName(tenantID int64) string {
	return strconv.FormatInt(tenantID, 10)
}

// TenantPolicyDBPath returns the compiled policy DB path for a tenant.
func TenantPolicyDBPath(policyDir string, tenantID int64) string {
	return filepath.Join(policyDir, TenantDirName(tenantID), "policy.db")
}

// TenantPolicyExists reports whether a compiled policy.db exists for the tenant.
func TenantPolicyExists(policyDir string, tenantID int64) bool {
	if strings.TrimSpace(policyDir) == "" || tenantID <= 0 {
		return false
	}
	_, err := os.Stat(TenantPolicyDBPath(policyDir, tenantID))
	return err == nil
}
