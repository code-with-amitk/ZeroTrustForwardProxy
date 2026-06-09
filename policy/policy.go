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
	"regexp"
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
	// Coach means request is allowed but logged for review.
	Coach Decision = "coach"
	// InspectDLP means request is allowed but inspected for data leakage.
	InspectDLP Decision = "inspect_dlp"
	// InspectMCP means request is allowed but inspected for MCP violations.
	InspectMCP Decision = "inspect_mcp"
	// None means no decision has been made yet.
	None Decision = "none"
)

// Engine is an immutable policy evaluator after load-time parsing.
type Engine struct {
	cfg    Config
	logger *zap.SugaredLogger
}

// Read policy.yaml, parse YAML, compile regex patterns and return Engine
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
	logger.Info("policy cfg loaded:", cfg)

	// Ensure deterministic default behavior when field is omitted.
	if cfg.DefaultAction == "" {
		cfg.DefaultAction = string(Allow)
	}

	// Compile regex patterns for all rules' domain conditions
	for i := range cfg.Rules {
		if err := compilePatterns(&cfg.Rules[i], logger); err != nil {
			logger.Warnf("Failed to compile patterns for rule %s: %v", cfg.Rules[i].Id, err)
		}
	}

	return &Engine{cfg: cfg, logger: logger}, nil
}

// compilePatterns compiles regex patterns for domain conditions in a rule
func compilePatterns(rule *Rule, logger *zap.SugaredLogger) error {
	rule.Conditions.Compiled = make([]*regexp.Regexp, 0)

	for _, domain := range rule.Conditions.Domains {
		compiled, err := regexp.Compile(domain)
		if err != nil {
			logger.Warnf("Failed to compile domain pattern '%s': %v", domain, err)
			continue
		}
		rule.Conditions.Compiled = append(rule.Conditions.Compiled, compiled)
	}
	return nil
}

// Decide returns action for the provided domain and method.
// Evaluates ordered rules from policy.yaml with regex domain matching.
// Returns first matching rule's action or default action if no match.
func (e *Engine) Decide(domain, method string) (Action, string) {
	if e.logger != nil {
		e.logger.Debug(utils.GetFunctionName())
	}

	var action Action
	var message string
	action = Action(e.cfg.DefaultAction)
	message = ""

	// Normalize values for case-insensitive matching
	domain = strings.ToLower(domain)
	method = strings.ToUpper(method)

	if e.logger != nil {
		e.logger.Debug("---Policy Evaluation Start---")
		e.logger.Debug("Domain:", domain, "Method:", method)
	}

	// Iterate through rules in order (first match wins)
	for _, rule := range e.cfg.Rules {
		if e.logger != nil {
			e.logger.Debug("Checking Rule Id: ", rule.Id, " Name: ", rule.Name)
		}

		// Check if domain matches any of the rule's conditions
		if matchesDomainCondition(rule.Conditions, domain) &&
			matchesMethodCondition(rule.Conditions, method) {
			if e.logger != nil {
				e.logger.Debug("Rule Id {", rule.Id, "} Matched. Action: ", rule.Action)
			}
			action = rule.Action
			message = rule.Message
			break
		} else {
			if e.logger != nil {
				e.logger.Debug("Rule Id {", rule.Id, "} Not Matched")
			}
		}
	}

	if e.logger != nil {
		e.logger.Debug("---Policy Evaluation End---")
		e.logger.Debug("Action: ", action)
		if message != "" {
			e.logger.Debug("Message: ", message)
		}
	}

	return action, message
}

// matchesDomainCondition checks if domain matches any pattern in the rule's domain conditions
func matchesDomainCondition(cond Conditions, domain string) bool {
	// If no domain conditions specified, match all domains
	if len(cond.Domains) == 0 {
		return true
	}

	// Check against compiled regex patterns
	for _, pattern := range cond.Compiled {
		if pattern.MatchString(domain) {
			return true
		}
	}
	return false
}

// matchesMethodCondition checks if method matches any in the rule's method conditions
func matchesMethodCondition(cond Conditions, method string) bool {
	// If no method conditions specified, match all methods
	if len(cond.Methods) == 0 {
		return true
	}

	// Check if method matches any in the list
	for _, m := range cond.Methods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}
