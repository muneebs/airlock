// Package config handles loading and saving of airlock project configuration.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Save writes the configuration to an airlock.toml file in the specified directory.
// The saved file includes helpful comments explaining each section.
func Save(dir string, cfg Config) error {
	path := filepath.Join(dir, "airlock.toml")

	content, err := FormatWithComments(cfg)
	if err != nil {
		return fmt.Errorf("format config: %w", err)
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}

// FormatWithComments formats the configuration as TOML with human-friendly comments.
// It uses WriteTOML for the actual serialization (DRY principle) and prepends comments.
func FormatWithComments(cfg Config) (string, error) {
	// Get the base TOML content using the existing serialization
	tomlBytes, err := WriteTOML(cfg)
	if err != nil {
		return "", fmt.Errorf("serialize config: %w", err)
	}

	// Parse TOML and inject comments between sections
	tomlStr := string(tomlBytes)
	
	var b strings.Builder

	// Header with generation info
	b.WriteString("# Airlock Configuration\n")
	b.WriteString(fmt.Sprintf("# Generated on %s\n", time.Now().Format("2006-01-02")))
	b.WriteString("#\n")
	b.WriteString("# Documentation: https://github.com/muneebs/airlock\n")
	b.WriteString("#\n\n")

	// Process TOML content section by section, adding comments
	sections := strings.Split(tomlStr, "\n\n")
	for i, section := range sections {
		if strings.TrimSpace(section) == "" {
			continue
		}

		// Add section comment based on section header
		sectionName := extractSectionName(section)
		comment := sectionComment(sectionName, cfg)
		if comment != "" {
			b.WriteString(comment)
			b.WriteString("\n")
		}

		b.WriteString(section)
		
		// Add separator between sections (but not after last)
		if i < len(sections)-1 {
			b.WriteString("\n\n")
		}
	}

	return b.String(), nil
}

// extractSectionName gets the section name from TOML content (e.g., "[vm]" -> "vm")
func extractSectionName(content string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			return strings.Trim(trimmed, "[]")
		}
	}
	return ""
}

// sectionComment returns the appropriate comment for a given section
func sectionComment(section string, cfg Config) string {
	switch section {
	case "security":
		return securitySectionComment(cfg.Security.Profile)
	case "vm":
		return vmSectionComment(cfg.VM)
	case "dev":
		return devSectionComment()
	case "runtime":
		return runtimeSectionComment(cfg.Runtime.Type)
	case "services":
		return servicesSectionComment()
	case "mounts":
		return mountsSectionComment()
	default:
		return ""
	}
}

func securitySectionComment(profile string) string {
	var desc string
	switch profile {
	case "strict":
		desc = "No host mounts, network locked. For untrusted software."
	case "cautious":
		desc = "Read-only mounts, network locked. Default for unknown software."
	case "dev":
		desc = "Read-write mounts, open network. For trusted development."
	case "trusted":
		desc = "Full access. Only for software you completely trust."
	default:
		desc = "Read-only mounts, network locked. Default for unknown software."
	}

	return fmt.Sprintf("# Security Profile: %s\n# %s", profile, desc)
}

func vmSectionComment(vm VMConfig) string {
	var b strings.Builder
	b.WriteString("# VM Resources\n")
	b.WriteString("# Configure the virtual machine hardware.\n")
	b.WriteString(fmt.Sprintf("# Current: %d CPU, %s RAM, %s disk", vm.CPU, vm.Memory, vm.Disk))
	return b.String()
}

func devSectionComment() string {
	return "# Development Settings\n# Configure ports and default commands."
}

func runtimeSectionComment(runtimeType string) string {
	return fmt.Sprintf("# Runtime Configuration\n# Auto-detected: %s", runtimeType)
}

func servicesSectionComment() string {
	return "# Services\n# Define background services to start automatically."
}

func mountsSectionComment() string {
	return "# Additional Mounts\n# Extra directories to mount into the sandbox.\n# Paths are relative to this config file."
}
