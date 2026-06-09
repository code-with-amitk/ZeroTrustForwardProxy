package policy

import "regexp"

// Action defines the policy decision outcome.
type Action string

const (
	ActionAllow      Action = "allow"
	ActionBlock      Action = "block"
	ActionCoach      Action = "coach"
	ActionInspectDLP Action = "inspect_dlp"
	ActionInspectMCP Action = "inspect_mcp"
)

// Rule defines one complete policy predicate and resulting action.
type Rule struct {
	Id         string        `yaml:"id"`
	Name       string        `yaml:"name"`
	Conditions Conditions    `yaml:"conditions"`
	MCP        MCPConditions `yaml:"mcp,omitempty"`
	Action     Action        `yaml:"action"`
	Message    string        `yaml:"message"`
}

// Conditions represents the matching criteria for a rule.
type Conditions struct {
	Domains  []string         `yaml:"domains"`
	Methods  []string         `yaml:"methods"`
	Groups   []string         `yaml:"groups"`
	Compiled []*regexp.Regexp `yaml:"-"` // Compiled regex patterns for domains
}

// MCPConditions defines MCP-specific matching criteria.
type MCPConditions struct {
	ToolNames    []string `yaml:"tool_names"`
	MessageTypes []string `yaml:"message_types"`
}

// Config models policy.yaml contents.
type Config struct {
	DefaultAction string `yaml:"default_action"`
	Rules         []Rule `yaml:"rules"`
}
