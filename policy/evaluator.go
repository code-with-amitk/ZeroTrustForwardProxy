package policy

// Evaluator resolves per-tenant policy decisions for the proxy data plane.
type Evaluator interface {
	Decide(tenantID int64, domain, method string) (Action, string, error)
}
