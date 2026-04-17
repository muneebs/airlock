package wizard

import (
	"strings"
	"testing"
)

func TestDeriveSandboxName(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected string
	}{
		{"current dir", ".", "sandbox"},
		{"simple path", "./my-project", "my-project"},
		{"nested path", "./projects/my-app", "my-app"},
		{"gh short", "gh:user/repo", "repo"},
		{"gh with git", "gh:user/repo.git", "repo"},
		{"github https", "https://github.com/user/repo", "repo"},
		{"github https with git", "https://github.com/user/repo.git", "repo"},
		{"path with extension", "./my-project.tar.gz", "my-project.tar"}, // Double extension behavior
		{"empty base", "./", "sandbox"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DeriveSandboxName(tt.source)
			if result != tt.expected {
				t.Errorf("DeriveSandboxName(%q) = %q, want %q", tt.source, result, tt.expected)
			}
		})
	}
}

func TestDeriveSandboxName_Sanitization(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected string
	}{
		{"with spaces", "./my project", "myproject"},  // Spaces are removed
		{"starting with number", "./1project", "_1project"}, // Numbers at start get underscore prefix
		{"with special chars", "./my@project#", "myproject"}, // Special chars removed
		{"empty after sanitize", "./@#$%", "_"}, // All special chars become underscore
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DeriveSandboxName(tt.source)
			if result != tt.expected {
				t.Errorf("DeriveSandboxName(%q) = %q, want %q", tt.source, result, tt.expected)
			}
		})
	}
}

func TestIsValidSandboxName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"valid simple", "my-project", true},
		{"valid with underscore", "my_project", true},
		{"valid with dot", "my.project", true},
		{"valid starts with underscore", "_myproject", true},
		{"empty", "", false},
		{"starts with number", "1project", false},
		{"contains space", "my project", false},
		{"contains slash", "my/project", false},
		{"contains special", "my@project", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidSandboxName(tt.input)
			if result != tt.expected {
				t.Errorf("isValidSandboxName(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetNetworkDescription(t *testing.T) {
	tests := []struct {
		name     string
		level    NetworkLevel
		expected string
	}{
		{"none", NetworkNone, "Locked immediately"},
		{"downloads", NetworkDownloads, "Lock after setup"},
		{"ongoing", NetworkOngoing, "Unlocked (ongoing access)"},
		{"unknown", NetworkLevel("unknown"), "Lock after setup"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getNetworkDescription(tt.level)
			if result != tt.expected {
				t.Errorf("getNetworkDescription(%q) = %q, want %q", tt.level, result, tt.expected)
			}
		})
	}
}

func TestBoolToYesNo(t *testing.T) {
	if boolToYesNo(true) != "Yes" {
		t.Errorf("boolToYesNo(true) = %q, want %q", boolToYesNo(true), "Yes")
	}
	if boolToYesNo(false) != "No" {
		t.Errorf("boolToYesNo(false) = %q, want %q", boolToYesNo(false), "No")
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"my-project", "my-project"},
		{"my_project", "my_project"},
		{"my.project", "my.project"},
		{"my project", "myproject"},       // Space is removed (not replaced with underscore)
		{"my@project", "myproject"},     // @ is removed
		{"1project", "_1project"},       // Numbers at start get underscore prefix
		{"@#$%", "_"},                   // All special chars become underscore (but only one at start)
		{"", "sandbox"},                 // Empty becomes sandbox
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeName(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeName(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsAlpha(t *testing.T) {
	tests := []struct {
		r    rune
		expected bool
	}{
		{'a', true},
		{'z', true},
		{'A', true},
		{'Z', true},
		{'0', false},
		{'9', false},
		{'-', false},
		{'_', false},
		{'@', false},
	}

	for _, tt := range tests {
		t.Run(string(tt.r), func(t *testing.T) {
			result := isAlpha(tt.r)
			if result != tt.expected {
				t.Errorf("isAlpha(%q) = %v, want %v", tt.r, result, tt.expected)
			}
		})
	}
}

func TestIsAlphaNum(t *testing.T) {
	tests := []struct {
		r    rune
		expected bool
	}{
		{'a', true},
		{'Z', true},
		{'0', true},
		{'9', true},
		{'-', false},
		{'_', false}, // Underscore is NOT alphanumeric in this implementation
		{'@', false},
	}

	for _, tt := range tests {
		t.Run(string(tt.r), func(t *testing.T) {
			result := isAlphaNum(tt.r)
			if result != tt.expected {
				t.Errorf("isAlphaNum(%q) = %v, want %v", tt.r, result, tt.expected)
			}
		})
	}
}

func TestTrustLevels_ContainExpected(t *testing.T) {
	levels := TrustLevels()
	
	// Verify we have all expected levels
	expectedLabels := map[string]bool{
		"strict":   false,
		"cautious": false,
		"dev":      false,
		"trusted":  false,
	}
	
	for _, level := range levels {
		for key := range expectedLabels {
			if strings.Contains(string(level.Level), key) {
				expectedLabels[key] = true
				break
			}
		}
	}
	
	for key, found := range expectedLabels {
		if !found {
			t.Errorf("TrustLevels() missing expected level: %s", key)
		}
	}
}

func TestResourceLevels_ValidValues(t *testing.T) {
	levels := ResourceLevels()
	
	// Verify all levels have valid resource values
	for _, level := range levels {
		if level.CPU < 1 {
			t.Errorf("%s: CPU must be >= 1, got %d", level.Level, level.CPU)
		}
		
		if !strings.HasSuffix(level.Memory, "GiB") {
			t.Errorf("%s: Memory should end with GiB, got %s", level.Level, level.Memory)
		}
	}
}

func TestNetworkLevels_ContainExpected(t *testing.T) {
	levels := NetworkLevels()
	
	// Verify we have all expected levels
	foundNone := false
	foundDownloads := false
	foundOngoing := false
	
	for _, level := range levels {
		switch level.Level {
		case NetworkNone:
			foundNone = true
		case NetworkDownloads:
			foundDownloads = true
		case NetworkOngoing:
			foundOngoing = true
		}
	}
	
	if !foundNone {
		t.Error("NetworkLevels() missing 'none'")
	}
	if !foundDownloads {
		t.Error("NetworkLevels() missing 'downloads'")
	}
	if !foundOngoing {
		t.Error("NetworkLevels() missing 'ongoing'")
	}
}
