// Package wizard provides an interactive TUI for creating airlock sandboxes.
// It translates user-friendly choices into technical configurations.
package wizard

import (
	"github.com/muneebs/airlock/internal/api"
	"github.com/muneebs/airlock/internal/config"
)

// TrustLevel represents the user's trust in the software they're running.
type TrustLevel string

const (
	TrustStrict   TrustLevel = "strict"
	TrustCautious TrustLevel = "cautious"
	TrustDev      TrustLevel = "dev"
	TrustTrusted  TrustLevel = "trusted"
)

// ResourceLevel represents the VM resource requirements.
type ResourceLevel string

const (
	ResourceLightweight ResourceLevel = "lightweight"
	ResourceStandard    ResourceLevel = "standard"
	ResourceHeavy       ResourceLevel = "heavy"
)

// NetworkLevel represents the network access requirements.
type NetworkLevel string

const (
	NetworkNone      NetworkLevel = "none"
	NetworkDownloads NetworkLevel = "downloads"
	NetworkOngoing   NetworkLevel = "ongoing"
)

// TrustLevelInfo provides user-facing descriptions for trust levels.
type TrustLevelInfo struct {
	Level       TrustLevel
	Label       string
	Description string
	Warning     string
}

// TrustLevels returns all available trust levels with their UI info.
func TrustLevels() []TrustLevelInfo {
	return []TrustLevelInfo{
		{
			Level:       TrustStrict,
			Label:       "🛡️  I don't trust it",
			Description: "Random scripts/tools from the internet",
			Warning:     "",
		},
		{
			Level:       TrustCautious,
			Label:       "⚠️  I'm not sure",
			Description: "Projects from unknown sources",
			Warning:     "",
		},
		{
			Level:       TrustDev,
			Label:       "🔧 I need to work on it",
			Description: "My own or team's projects",
			Warning:     "Allows network and file access. The software can modify your project files.",
		},
		{
			Level:       TrustTrusted,
			Label:       "✅ I trust it completely",
			Description: "Software I authored or reviewed",
			Warning:     "Warning: This grants full system access. Only choose this for software you completely trust.",
		},
	}
}

// ResourceLevelInfo provides user-facing descriptions for resource levels.
type ResourceLevelInfo struct {
	Level       ResourceLevel
	Label       string
	Description string
	CPU         int
	Memory      string
}

// ResourceLevels returns all available resource levels.
func ResourceLevels() []ResourceLevelInfo {
	return []ResourceLevelInfo{
		{
			Level:       ResourceLightweight,
			Label:       "🪶 Lightweight",
			Description: "Scripts, small tools",
			CPU:         1,
			Memory:      "2GiB",
		},
		{
			Level:       ResourceStandard,
			Label:       "📦 Standard",
			Description: "Most apps",
			CPU:         2,
			Memory:      "4GiB",
		},
		{
			Level:       ResourceHeavy,
			Label:       "🚀 Heavy",
			Description: "Builds, databases, large projects",
			CPU:         4,
			Memory:      "8GiB",
		},
	}
}

// NetworkLevelInfo provides user-facing descriptions for network levels.
type NetworkLevelInfo struct {
	Level       NetworkLevel
	Label       string
	Description string
	Warning     string
	LockAfter   bool
}

// NetworkLevels returns all available network levels.
func NetworkLevels() []NetworkLevelInfo {
	return []NetworkLevelInfo{
		{
			Level:       NetworkNone,
			Label:       "🔒 None",
			Description: "Completely offline",
			Warning:     "",
			LockAfter:   false,
		},
		{
			Level:       NetworkDownloads,
			Label:       "⬇️  Downloads only",
			Description: "Install dependencies, then lock",
			Warning:     "",
			LockAfter:   true,
		},
		{
			Level:       NetworkOngoing,
			Label:       "🌐 Ongoing access",
			Description: "Needs internet continuously",
			Warning:     "Warning: This allows the software to communicate with external servers continuously.",
			LockAfter:   false,
		},
	}
}

// MapTrustLevelToProfile returns the profile name for a trust level.
func MapTrustLevelToProfile(level TrustLevel) string {
	switch level {
	case TrustStrict:
		return "strict"
	case TrustCautious:
		return "cautious"
	case TrustDev:
		return "dev"
	case TrustTrusted:
		return "trusted"
	default:
		return "cautious"
	}
}

// MapResourceLevel returns the CPU and memory for a resource level.
func MapResourceLevel(level ResourceLevel) (cpu int, memory string) {
	switch level {
	case ResourceLightweight:
		return 1, "2GiB"
	case ResourceStandard:
		return 2, "4GiB"
	case ResourceHeavy:
		return 4, "8GiB"
	default:
		return 2, "4GiB"
	}
}

// IsInsecureChoice returns true if the choice requires a security warning.
func IsInsecureChoice(level TrustLevel) bool {
	return level == TrustDev || level == TrustTrusted
}

// IsInsecureNetwork returns true if the network choice requires a warning.
func IsInsecureNetwork(level NetworkLevel) bool {
	return level == NetworkOngoing
}

// Runtime keys match ProvisionOptions booleans and ToolsConfig fields.
const (
	RuntimeNode   = "node"
	RuntimeBun    = "bun"
	RuntimeDocker = "docker"
)

// AI tool short-name keys. These must match the strings accepted by
// api.ProvisionOptions.AITools and lima provisioner's aiToolStep switch.
const (
	AIToolClaudeCode = "claude-code"
	AIToolGemini     = "gemini"
	AIToolCodex      = "codex"
	AIToolOpenCode   = "opencode"
	AIToolOllama     = "ollama"
)

// AIToolInfo describes an AI tool option shown in the wizard.
type AIToolInfo struct {
	Key        string
	Label      string // shown in multi-select
	ShortLabel string // shown in summary
}

// AIToolRequiresNpm reports whether an AI tool key is installed via npm and
// therefore implies Node.js must be installed. Must stay in sync with the
// provisioner registry in internal/vm/lima.
func AIToolRequiresNpm(key string) bool {
	switch key {
	case AIToolClaudeCode, AIToolGemini, AIToolCodex:
		return true
	}
	return false
}

// AITools returns all AI tool options the wizard offers. Declared once here
// so the wizard UI and tests share the same source of truth.
func AITools() []AIToolInfo {
	return []AIToolInfo{
		{Key: AIToolClaudeCode, Label: "Claude Code (Anthropic)", ShortLabel: "Claude Code"},
		{Key: AIToolGemini, Label: "Gemini CLI (Google)", ShortLabel: "Gemini CLI"},
		{Key: AIToolCodex, Label: "Codex CLI (OpenAI)", ShortLabel: "Codex CLI"},
		{Key: AIToolOpenCode, Label: "OpenCode", ShortLabel: "OpenCode"},
		{Key: AIToolOllama, Label: "Ollama (local LLM runtime)", ShortLabel: "Ollama"},
	}
}

// WizardResult contains the final configuration from the wizard.
type WizardResult struct {
	Source        string
	Name          string
	TrustLevel    TrustLevel
	ResourceLevel ResourceLevel
	NetworkLevel  NetworkLevel
	InstallNode   bool
	InstallBun    bool
	InstallDocker bool
	AITools       []string
	StartAtLogin  bool
	SaveConfig    bool
	CreateNow     bool
}

// ToProvisionOptions converts the wizard tool selections into the
// api.ProvisionOptions the Provisioner consumes. AI tools are deduplicated
// preserving first-seen order.
func (r *WizardResult) ToProvisionOptions(nodeVersion int) api.ProvisionOptions {
	// Deduplicate AI tools preserving first-seen order
	seen := make(map[string]bool)
	uniqueAITools := make([]string, 0, len(r.AITools))
	for _, tool := range r.AITools {
		if !seen[tool] {
			seen[tool] = true
			uniqueAITools = append(uniqueAITools, tool)
		}
	}

	return api.ProvisionOptions{
		NodeVersion:   nodeVersion,
		InstallNode:   r.InstallNode,
		InstallBun:    r.InstallBun,
		InstallDocker: r.InstallDocker,
		AITools:       uniqueAITools,
	}
}

// ToSandboxSpec converts wizard result to API sandbox spec.
func (r *WizardResult) ToSandboxSpec(runtime string) api.SandboxSpec {
	cpu, memory := MapResourceLevel(r.ResourceLevel)
	profile := MapTrustLevelToProfile(r.TrustLevel)

	defaults := config.Defaults()
	lockAfter := r.NetworkLevel != NetworkOngoing
	return api.SandboxSpec{
		Name:                  r.Name,
		Source:                r.Source,
		Runtime:               runtime,
		Profile:               profile,
		CPU:                   &cpu,
		Memory:                memory,
		Disk:                  defaults.VM.Disk,
		Ports:                 defaults.Dev.Ports,
		StartAtLogin:          r.StartAtLogin,
		LockNetworkAfterSetup: &lockAfter,
	}
}

// ToConfig converts wizard result to Config struct. Unspecified fields
// inherit canonical values from config.Defaults() so callers (e.g. the
// provisioner) see sensible defaults like NodeVersion and Disk.
func (r *WizardResult) ToConfig(runtime string) config.Config {
	cpu, memory := MapResourceLevel(r.ResourceLevel)
	profile := MapTrustLevelToProfile(r.TrustLevel)

	cfg := config.Defaults()
	cfg.VM.CPU = cpu
	cfg.VM.Memory = memory
	cfg.Security.Profile = profile
	cfg.Runtime.Type = runtime
	cfg.StartAtLogin = r.StartAtLogin
	cfg.Tools = config.ToolsConfig{
		Node:    r.InstallNode,
		Bun:     r.InstallBun,
		Docker:  r.InstallDocker,
		AITools: append([]string(nil), r.AITools...),
	}
	return cfg
}

// NeedsNetworkLock returns true if the network should be locked after setup.
func (r *WizardResult) NeedsNetworkLock() bool {
	return r.NetworkLevel == NetworkDownloads
}
