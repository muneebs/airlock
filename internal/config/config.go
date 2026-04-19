// Package config handles loading and validation of airlock project configuration
// from both TOML and YAML formats. It uses a single struct representation with
// Viper for format detection and merging.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// Config represents an airlock project configuration. This is the single source
// of truth — both TOML and YAML map to this struct with zero semantic difference.
type Config struct {
	VM           VMConfig       `json:"vm" yaml:"vm" toml:"vm"`
	Dev          DevConfig      `json:"dev" yaml:"dev" toml:"dev"`
	Runtime      RuntimeConfig  `json:"runtime" yaml:"runtime" toml:"runtime"`
	Security     SecurityConfig `json:"security" yaml:"security" toml:"security"`
	Services     ServicesConfig `json:"services" yaml:"services" toml:"services"`
	Tools        ToolsConfig    `json:"tools" yaml:"tools" toml:"tools"`
	Mounts       []MountConfig  `json:"mounts" yaml:"mounts" toml:"mounts"`
	StartAtLogin bool           `json:"start_at_login,omitempty" yaml:"start_at_login,omitempty" toml:"start_at_login,omitempty"`
}

// VMConfig controls the virtual machine resource allocation.
type VMConfig struct {
	CPU         int    `json:"cpu,omitempty" yaml:"cpu,omitempty" toml:"cpu,omitempty"`
	Memory      string `json:"memory,omitempty" yaml:"memory,omitempty" toml:"memory,omitempty"`
	Disk        string `json:"disk,omitempty" yaml:"disk,omitempty" toml:"disk,omitempty"`
	NodeVersion int    `json:"node_version,omitempty" yaml:"node_version,omitempty" toml:"node_version,omitempty"`
}

// DevConfig controls development mode settings.
type DevConfig struct {
	Ports   string `json:"ports,omitempty" yaml:"ports,omitempty" toml:"ports,omitempty"`
	Command string `json:"command,omitempty" yaml:"command,omitempty" toml:"command,omitempty"`
}

// RuntimeConfig overrides auto-detected runtime settings.
type RuntimeConfig struct {
	Type    string `json:"type,omitempty" yaml:"type,omitempty" toml:"type,omitempty"`
	Install string `json:"install,omitempty" yaml:"install,omitempty" toml:"install,omitempty"`
	Run     string `json:"run,omitempty" yaml:"run,omitempty" toml:"run,omitempty"`
	Docker  bool   `json:"docker,omitempty" yaml:"docker,omitempty" toml:"docker,omitempty"`
}

// SecurityConfig controls the security profile applied to the sandbox.
type SecurityConfig struct {
	Profile       string `json:"profile,omitempty" yaml:"profile,omitempty" toml:"profile,omitempty"`
	AllowOutbound *bool  `json:"allow_outbound,omitempty" yaml:"allow_outbound,omitempty" toml:"allow_outbound,omitempty"`
	AllowDocker   *bool  `json:"allow_docker,omitempty" yaml:"allow_docker,omitempty" toml:"allow_docker,omitempty"`
}

// ServicesConfig defines background services to start.
type ServicesConfig struct {
	Compose string `json:"compose,omitempty" yaml:"compose,omitempty" toml:"compose,omitempty"`
}

// ToolsConfig selects which runtimes and AI tools are installed during
// provisioning. All fields default to false/empty — callers opt in.
type ToolsConfig struct {
	Node    bool     `json:"node,omitempty" yaml:"node,omitempty" toml:"node,omitempty"`
	Bun     bool     `json:"bun,omitempty" yaml:"bun,omitempty" toml:"bun,omitempty"`
	Docker  bool     `json:"docker,omitempty" yaml:"docker,omitempty" toml:"docker,omitempty"`
	AITools []string `json:"ai_tools,omitempty" yaml:"ai_tools,omitempty" toml:"ai_tools,omitempty"`
}

// MountConfig defines an additional host directory to mount.
type MountConfig struct {
	Path     string `json:"path" yaml:"path" toml:"path"`
	Writable *bool  `json:"writable,omitempty" yaml:"writable,omitempty" toml:"writable,omitempty"`
	Inotify  bool   `json:"inotify,omitempty" yaml:"inotify,omitempty" toml:"inotify,omitempty"`
}

// Defaults returns a Config populated with sensible defaults.
func Defaults() Config {
	cpu := 2
	return Config{
		VM: VMConfig{
			CPU:         cpu,
			Memory:      "4GiB",
			Disk:        "20GiB",
			NodeVersion: 22,
		},
		Dev: DevConfig{
			Ports: "3000:9999",
		},
		Runtime: RuntimeConfig{
			Type: "",
		},
		Security: SecurityConfig{
			Profile: "cautious",
		},
		Tools: ToolsConfig{
			Node:    false,
			Bun:     false,
			Docker:  false,
			AITools: nil,
		},
		Mounts: nil,
	}
}

// ConfigFile looks for an airlock config file in the given directory.
// Returns the path and format ("toml" or "yaml"), or an empty string if none found.
// TOML is preferred over YAML when both exist.
func ConfigFile(dir string) (path string, format string) {
	tomlPath := filepath.Join(dir, "airlock.toml")
	if _, err := os.Stat(tomlPath); err == nil {
		return tomlPath, "toml"
	}
	yamlPath := filepath.Join(dir, "airlock.yaml")
	if _, err := os.Stat(yamlPath); err == nil {
		return yamlPath, "yaml"
	}
	ymlPath := filepath.Join(dir, "airlock.yml")
	if _, err := os.Stat(ymlPath); err == nil {
		return ymlPath, "yaml"
	}
	return "", ""
}

// Load reads configuration from a directory. It looks for airlock.toml first,
// then airlock.yaml, then airlock.yml. If none found, it returns defaults.
// Config values are merged onto defaults: explicit values override defaults,
// unset values fall through.
func Load(dir string) (Config, error) {
	path, format := ConfigFile(dir)
	if path == "" {
		return Defaults(), nil
	}
	return loadFile(path, format)
}

func loadFile(path, format string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	switch format {
	case "toml":
		if err := toml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse TOML config %s: %w", path, err)
		}
	case "yaml":
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, fmt.Errorf("parse YAML config %s: %w", path, err)
		}
	default:
		return Config{}, fmt.Errorf("unsupported config format: %s", format)
	}

	if err := validate(cfg); err != nil {
		return Config{}, fmt.Errorf("invalid config %s: %w", path, err)
	}

	return mergeWithDefaults(cfg), nil
}

func mergeWithDefaults(cfg Config) Config {
	defaults := Defaults()

	if cfg.VM.CPU == 0 {
		cfg.VM.CPU = defaults.VM.CPU
	}
	if cfg.VM.Memory == "" {
		cfg.VM.Memory = defaults.VM.Memory
	}
	if cfg.VM.Disk == "" {
		cfg.VM.Disk = defaults.VM.Disk
	}
	if cfg.VM.NodeVersion == 0 {
		cfg.VM.NodeVersion = defaults.VM.NodeVersion
	}
	if cfg.Dev.Ports == "" {
		cfg.Dev.Ports = defaults.Dev.Ports
	}
	if cfg.Security.Profile == "" {
		cfg.Security.Profile = defaults.Security.Profile
	}

	// Merge Tools fields: copy defaults for false/empty fields
	if !cfg.Tools.Node {
		cfg.Tools.Node = defaults.Tools.Node
	}
	if !cfg.Tools.Bun {
		cfg.Tools.Bun = defaults.Tools.Bun
	}
	if !cfg.Tools.Docker {
		cfg.Tools.Docker = defaults.Tools.Docker
	}
	if cfg.Tools.AITools == nil {
		cfg.Tools.AITools = defaults.Tools.AITools
	}

	for i := range cfg.Mounts {
		if cfg.Mounts[i].Writable == nil {
			w := false
			cfg.Mounts[i].Writable = &w
		}
	}

	return cfg
}

// validate enforces structural rules owned by the config package itself:
// mount paths must be relative and free of traversal, services.compose must
// be relative. Profile and runtime membership are NOT checked here — those
// are open sets owned by profile.Registry and detect.CompositeDetector, and
// are checked via ValidateDynamic once those registries are available. This
// keeps config free of hardcoded plugin lists (PRINCIPLES.md §4 DRY, §5 OCP).
func validate(cfg Config) error {
	if cfg.Services.Compose != "" {
		if strings.HasPrefix(cfg.Services.Compose, "/") {
			return fmt.Errorf("services.compose must be a relative path, got: %s", cfg.Services.Compose)
		}
	}

	for _, m := range cfg.Mounts {
		if m.Path == "" {
			return fmt.Errorf("mounts[].path is required")
		}
		if strings.HasPrefix(m.Path, "/") {
			return fmt.Errorf("mounts[].path must be relative, got: %s", m.Path)
		}
		for _, part := range strings.Split(m.Path, string(filepath.Separator)) {
			if part == ".." {
				return fmt.Errorf("mounts[].path must be relative and must not contain path traversal sequences, got: %s", m.Path)
			}
		}
	}

	return nil
}

// ValidateDynamic checks cfg against the open sets of known profiles and
// runtime types. Callers pass in the currently-registered names (from
// api.ProfileRegistry.List() and api.RuntimeDetector.SupportedTypes()), so
// adding a new profile or runtime requires no edit to this package.
//
// An empty profile or runtime is always allowed (means "use default" or
// "auto-detect"). Nil slices skip the check for that dimension.
func ValidateDynamic(cfg Config, profileNames []string, runtimeTypes []string) error {
	if cfg.Security.Profile != "" && profileNames != nil {
		if !contains(profileNames, cfg.Security.Profile) {
			return fmt.Errorf("unknown security profile: %q (valid: %s)", cfg.Security.Profile, strings.Join(profileNames, ", "))
		}
	}

	if cfg.Runtime.Type != "" && runtimeTypes != nil {
		if !contains(runtimeTypes, cfg.Runtime.Type) {
			return fmt.Errorf("unknown runtime type: %q (valid: %s)", cfg.Runtime.Type, strings.Join(runtimeTypes, ", "))
		}
	}

	return nil
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// WriteTOML serializes a Config to TOML format.
func WriteTOML(cfg Config) ([]byte, error) {
	return toml.Marshal(cfg)
}

// WriteYAML serializes a Config to YAML format.
func WriteYAML(cfg Config) ([]byte, error) {
	return yaml.Marshal(cfg)
}