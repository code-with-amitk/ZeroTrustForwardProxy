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
	"context"
	"os"
	"regexp"
	"strings"
	"sync"
	"zerotrust-forward-proxy/utils"

	"github.com/fsnotify/fsnotify"
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

// Engine evaluates policy rules.  cfg is swapped atomically on hot-reload.
type Engine struct {
	mu     sync.RWMutex
	cfg    Config
	path   string
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

	return &Engine{cfg: cfg, path: path, logger: logger}, nil
}

// reload reads the policy file from disk and swaps in the new config under a
// write lock.  Called from Watch on every fsnotify event.
func (e *Engine) reload() {
	b, err := os.ReadFile(e.path)
	if err != nil {
		e.logger.Warnf("policy hot-reload: read %s: %v", e.path, err)
		return
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		e.logger.Warnf("policy hot-reload: parse %s: %v", e.path, err)
		return
	}
	if cfg.DefaultAction == "" {
		cfg.DefaultAction = string(Allow)
	}
	for i := range cfg.Rules {
		if err := compilePatterns(&cfg.Rules[i], e.logger); err != nil {
			e.logger.Warnf("policy hot-reload: compile patterns rule %s: %v", cfg.Rules[i].Id, err)
		}
	}
	e.mu.Lock()
	e.cfg = cfg
	e.mu.Unlock()
	e.logger.Info("policy hot-reloaded", "file", e.path, "rules", len(cfg.Rules))
}

// Watch starts a background goroutine that watches the policy file for changes
// and reloads it when a write or create event is detected.  The goroutine exits
// when ctx is cancelled.  Call this once from main after Load().
func (e *Engine) Watch(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	if err := watcher.Add(e.path); err != nil {
		_ = watcher.Close()
		return err
	}
	e.logger.Info("policy file watcher started", "file", e.path)
	go func() {
		defer watcher.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// Write and Create cover both direct edits and ConfigMap
				// atomic-rename updates (rename-then-symlink pattern used by k8s).
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
					e.logger.Info("policy file changed, reloading", "op", event.Op, "file", event.Name)
					e.reload()
					// Re-add watch after rename/create in case the inode changed.
					_ = watcher.Add(e.path)
				}
			case watchErr, ok := <-watcher.Errors:
				if !ok {
					return
				}
				e.logger.Warnf("policy watcher error: %v", watchErr)
			}
		}
	}()
	return nil
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

	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()

	var action Action
	var message string
	action = Action(cfg.DefaultAction)
	message = ""

	// Normalize values for case-insensitive matching
	domain = strings.ToLower(domain)
	method = strings.ToUpper(method)

	if e.logger != nil {
		e.logger.Debug("---Policy Evaluation Start---")
		e.logger.Debug("Domain:", domain, "Method:", method)
	}

	// Iterate through rules in order (first match wins)
	for _, rule := range cfg.Rules {
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
