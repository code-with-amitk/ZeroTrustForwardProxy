// Package policy implements user/domain-based access decisions.
//
// Architecture fit:
//   - The proxy request path calls this package after identity extraction to
//     decide whether traffic is allowed to proceed.
//
// Key responsibilities:
// - Load YAML policy definitions.
// - Evaluate ordered rules with wildcard support.
// - Return explicit allow/block decisions.
//
// Design decisions:
// - Rule order is significant (first match wins).
// - Default action applies only when no rule matches.
package policy

import (
	"os"
	"strings"
	"zerotrust-forward-proxy/utils"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type Decision string

const (
	// Allow means request processing may continue.
	Allow Decision = "allow"
	// Block means request must be denied immediately.
	Block Decision = "block"
	// None
	None Decision = "none"
)

// Rule defines one policy predicate and resulting action.
type Rule struct {
	User   string `yaml:"user"`
	Domain string `yaml:"domain"`
	Action string `yaml:"action"`
}

// Config models policy.yaml contents.
type Config struct {
	DefaultAction string `yaml:"default_action"`
	Rules         []Rule `yaml:"rules"`
}

// Engine is an immutable policy evaluator after load-time parsing.
type Engine struct {
	cfg    Config
	logger *zap.SugaredLogger
}

// Read config.yaml, map fields to Config struct and return
func Load(logger *zap.SugaredLogger, path string) (*Engine, error) {
	utils.GetFunctionName()

	// Read contents of file as bytes
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	// Store bytes into policy config structure.
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	logger.Info("policy cfg:", cfg)

	// Ensure deterministic default behavior when field is omitted.
	if cfg.DefaultAction == "" {
		cfg.DefaultAction = string(Allow)
	}
	return &Engine{cfg: cfg, logger: logger}, nil
}

// Decide returns allow/block for the provided user and domain.
// Inputs:
// - user: resolved identity subject.
// - domain: target host without port.
// Outputs:
// - Decision value, based on first matching rule or default action.
// Assumptions:
// - Matching is case-insensitive.
// - Rule order in YAML reflects policy priority.
func (e *Engine) Decide(user, domain string) Decision {
	e.logger.Debug(utils.GetFunctionName())
	var action Decision
	action = None

	// Normalize values so matching remains case-insensitive.
	user = strings.ToLower(user)
	domain = strings.ToLower(domain)
	e.logger.Debug("-----------Policy Evaluation Start------------")

	for _, r := range e.cfg.Rules {
		e.logger.Debug("Rule's User: ", r.User, ", Incoming User from JWT: ", user)
		e.logger.Debug("Rule's domain: ", r.Domain, ", Incoming Domain from HTTP Req: ", domain)
		if matches(r.User, user) && matchesDomain(r.Domain, domain) {
			e.logger.Debug("Rule Matched!!")
			// Return the action
			action = Decision(r.Action)
			break
		} else {
			e.logger.Debug("Rule Not Matched..")
		}
	}
	if action == None {
		// Fall back to configured default when no rule matched.
		action = Decision(e.cfg.DefaultAction)
	}

	e.logger.Debug("-----------Policy Evaluation End------------")
	e.logger.Debug("Action: ", action)

	return action
}

// matches compares a scalar value against exact-or-wildcard pattern.
//
// Inputs:
// - pattern: literal value or "*".
// - value: request value.
//
// Outputs:
// - true when pattern matches value.
//
// Side effects:
// - None.
//
// Assumptions:
// - Empty pattern is treated as wildcard.
func matches(pattern, value string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	// Use case-insensitive compare for operator convenience.
	return strings.EqualFold(pattern, value)
}

// matchesDomain compares host against exact or suffix wildcard pattern.
//
// Inputs:
// - pattern: "*", "*.example.com", or exact host.
// - domain: normalized request domain.
//
// Outputs:
// - true when domain satisfies pattern.
//
// Side effects:
// - None.
//
// Assumptions:
// - Pattern "*.example.com" matches subdomains by suffix.
func matchesDomain(pattern, domain string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	// Normalize both values for case-insensitive host matching.
	pattern = strings.ToLower(pattern)
	domain = strings.ToLower(domain)
	// Handle wildcard-subdomain syntax via suffix check.
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(domain, pattern[1:])
	}
	return pattern == domain
}
