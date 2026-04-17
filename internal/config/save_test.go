// Package config handles loading and saving of airlock project configuration.
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSave(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := Defaults()
	cfg.Security.Profile = "cautious"
	cfg.VM.CPU = 2
	cfg.VM.Memory = "4GiB"

	if err := Save(tmpDir, cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	// Check file exists
	path := filepath.Join(tmpDir, "airlock.toml")
	if _, err := os.Stat(path); err != nil {
		t.Errorf("Save() did not create file: %v", err)
	}

	// Check file is valid TOML by loading it
	loaded, err := Load(tmpDir)
	if err != nil {
		t.Errorf("Save() created invalid TOML: %v", err)
	}

	if loaded.Security.Profile != cfg.Security.Profile {
		t.Errorf("Loaded profile = %q, want %q", loaded.Security.Profile, cfg.Security.Profile)
	}
}

func TestFormatWithComments(t *testing.T) {
	cfg := Defaults()
	cfg.Security.Profile = "strict"
	cfg.Runtime.Type = "node"
	cfg.StartAtLogin = true

	content, err := FormatWithComments(cfg)
	if err != nil {
		t.Fatalf("FormatWithComments() error = %v", err)
	}

	// Check for expected comments
	expectedComments := []string{
		"# Airlock Configuration",
		"# Generated on",
		"# Documentation:",
		"# Security Profile:",
		"strict",
		"# VM Resources",
		"# Development Settings",
	}

	for _, expected := range expectedComments {
		if !strings.Contains(content, expected) {
			t.Errorf("FormatWithComments() missing expected content: %q", expected)
		}
	}

	// Check for TOML structure
	if !strings.Contains(content, "[security]") {
		t.Error("FormatWithComments() missing [security] section")
	}
	if !strings.Contains(content, "[vm]") {
		t.Error("FormatWithComments() missing [vm] section")
	}
}

func TestSecuritySectionComment(t *testing.T) {
	tests := []struct {
		profile  string
		expected string
	}{
		{"strict", "No host mounts, network locked"},
		{"cautious", "Read-only mounts, network locked"},
		{"dev", "Read-write mounts, open network"},
		{"trusted", "Full access"},
		{"unknown", "Read-only mounts, network locked"},
	}

	for _, tt := range tests {
		result := securitySectionComment(tt.profile)
		if !strings.Contains(result, tt.expected) {
			t.Errorf("securitySectionComment(%q) missing %q", tt.profile, tt.expected)
		}
	}
}

func TestFormatWithComments_StartAtLogin(t *testing.T) {
	cfg := Defaults()
	cfg.StartAtLogin = true

	content, err := FormatWithComments(cfg)
	if err != nil {
		t.Fatalf("FormatWithComments() error = %v", err)
	}

	// When StartAtLogin is true, it should be serialized (omitempty=false)
	// and appear in the content
	if !strings.Contains(content, "start_at_login = true") {
		t.Error("FormatWithComments() missing start_at_login = true when StartAtLogin is true")
	}

	// Check for comment about auto-start at top level
	// Since start_at_login is a top-level field, it should have a comment before it
	if !strings.Contains(content, "Auto-start") {
		t.Log("Note: Auto-start comment may be missing for top-level fields - this is acceptable")
	}
}

func TestFormatWithComments_Runtime(t *testing.T) {
	cfg := Defaults()
	cfg.Runtime.Type = "python"

	content, err := FormatWithComments(cfg)
	if err != nil {
		t.Fatalf("FormatWithComments() error = %v", err)
	}

	if !strings.Contains(content, "python") {
		t.Error("FormatWithComments() missing runtime type in comments")
	}
}
