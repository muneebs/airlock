package wizard

import (
	"testing"
)

func TestMapTrustLevelToProfile(t *testing.T) {
	tests := []struct {
		name     string
		level    TrustLevel
		expected string
	}{
		{"strict", TrustStrict, "strict"},
		{"cautious", TrustCautious, "cautious"},
		{"dev", TrustDev, "dev"},
		{"trusted", TrustTrusted, "trusted"},
		{"unknown", TrustLevel("unknown"), "cautious"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MapTrustLevelToProfile(tt.level)
			if result != tt.expected {
				t.Errorf("MapTrustLevelToProfile(%q) = %q, want %q", tt.level, result, tt.expected)
			}
		})
	}
}

func TestMapResourceLevel(t *testing.T) {
	tests := []struct {
		name        string
		level       ResourceLevel
		expectedCPU int
		expectedMem string
	}{
		{"lightweight", ResourceLightweight, 1, "2GiB"},
		{"standard", ResourceStandard, 2, "4GiB"},
		{"heavy", ResourceHeavy, 4, "8GiB"},
		{"unknown", ResourceLevel("unknown"), 2, "4GiB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpu, mem := MapResourceLevel(tt.level)
			if cpu != tt.expectedCPU {
				t.Errorf("MapResourceLevel(%q) CPU = %d, want %d", tt.level, cpu, tt.expectedCPU)
			}
			if mem != tt.expectedMem {
				t.Errorf("MapResourceLevel(%q) Memory = %q, want %q", tt.level, mem, tt.expectedMem)
			}
		})
	}
}

func TestIsInsecureChoice(t *testing.T) {
	tests := []struct {
		name     string
		level    TrustLevel
		expected bool
	}{
		{"strict is safe", TrustStrict, false},
		{"cautious is safe", TrustCautious, false},
		{"dev is insecure", TrustDev, true},
		{"trusted is insecure", TrustTrusted, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsInsecureChoice(tt.level)
			if result != tt.expected {
				t.Errorf("IsInsecureChoice(%q) = %v, want %v", tt.level, result, tt.expected)
			}
		})
	}
}

func TestIsInsecureNetwork(t *testing.T) {
	tests := []struct {
		name     string
		level    NetworkLevel
		expected bool
	}{
		{"none is safe", NetworkNone, false},
		{"downloads is safe", NetworkDownloads, false},
		{"ongoing is insecure", NetworkOngoing, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsInsecureNetwork(tt.level)
			if result != tt.expected {
				t.Errorf("IsInsecureNetwork(%q) = %v, want %v", tt.level, result, tt.expected)
			}
		})
	}
}

func TestWizardResult_ToSandboxSpec(t *testing.T) {
	result := WizardResult{
		Name:          "my-sandbox",
		Source:        "./my-project",
		TrustLevel:    TrustCautious,
		ResourceLevel: ResourceStandard,
		NetworkLevel:  NetworkDownloads,
		StartAtLogin:  false,
		SaveConfig:    true,
		CreateNow:     true,
	}

	spec := result.ToSandboxSpec("node")

	if spec.Name != "my-sandbox" {
		t.Errorf("Name = %q, want %q", spec.Name, "my-sandbox")
	}
	if spec.Source != "./my-project" {
		t.Errorf("Source = %q, want %q", spec.Source, "./my-project")
	}
	if spec.Runtime != "node" {
		t.Errorf("Runtime = %q, want %q", spec.Runtime, "node")
	}
	if spec.Profile != "cautious" {
		t.Errorf("Profile = %q, want %q", spec.Profile, "cautious")
	}
	if spec.CPU == nil || *spec.CPU != 2 {
		t.Errorf("CPU = %v, want 2", spec.CPU)
	}
	if spec.Memory != "4GiB" {
		t.Errorf("Memory = %q, want %q", spec.Memory, "4GiB")
	}
}

func TestWizardResult_NeedsNetworkLock(t *testing.T) {
	tests := []struct {
		name     string
		level    NetworkLevel
		expected bool
	}{
		{"none does not lock after", NetworkNone, false},
		{"downloads locks after", NetworkDownloads, true},
		{"ongoing does not lock after", NetworkOngoing, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := WizardResult{NetworkLevel: tt.level}
			if got := result.NeedsNetworkLock(); got != tt.expected {
				t.Errorf("NeedsNetworkLock() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTrustLevels(t *testing.T) {
	levels := TrustLevels()
	if len(levels) != 4 {
		t.Fatalf("TrustLevels() returned %d levels, want 4", len(levels))
	}

	// Check all expected levels exist
	expected := []TrustLevel{TrustStrict, TrustCautious, TrustDev, TrustTrusted}
	for i, exp := range expected {
		if levels[i].Level != exp {
			t.Errorf("TrustLevels()[%d].Level = %q, want %q", i, levels[i].Level, exp)
		}
	}

	// Check that dev and trusted have warnings
	for _, level := range levels {
		if level.Level == TrustDev || level.Level == TrustTrusted {
			if level.Warning == "" {
				t.Errorf("TrustLevels() %q should have a warning", level.Level)
			}
		}
	}
}

func TestResourceLevels(t *testing.T) {
	levels := ResourceLevels()
	if len(levels) != 3 {
		t.Fatalf("ResourceLevels() returned %d levels, want 3", len(levels))
	}

	// Check all levels have valid CPU and memory
	for _, level := range levels {
		if level.CPU < 1 {
			t.Errorf("ResourceLevels() %q has invalid CPU: %d", level.Level, level.CPU)
		}
		if level.Memory == "" {
			t.Errorf("ResourceLevels() %q has empty Memory", level.Level)
		}
	}
}

func TestAITools_Keys(t *testing.T) {
	tools := AITools()
	want := map[string]bool{
		AIToolClaudeCode: false,
		AIToolGemini:     false,
		AIToolCodex:      false,
		AIToolOpenCode:   false,
		AIToolOllama:     false,
	}
	for _, info := range tools {
		if info.Key == "" {
			t.Errorf("AITools() entry has empty Key: %+v", info)
		}
		if info.Label == "" {
			t.Errorf("AITools() entry has empty Label: %+v", info)
		}
		if _, ok := want[info.Key]; !ok {
			t.Errorf("AITools() returned unexpected key %q", info.Key)
			continue
		}
		want[info.Key] = true
	}
	for k, found := range want {
		if !found {
			t.Errorf("AITools() missing expected key %q", k)
		}
	}
}

func TestWizardResult_ToProvisionOptions(t *testing.T) {
	r := WizardResult{
		InstallNode:   true,
		InstallBun:    false,
		InstallDocker: true,
		AITools:       []string{AIToolClaudeCode, AIToolOllama},
	}

	opts := r.ToProvisionOptions(20)

	if opts.NodeVersion != 20 {
		t.Errorf("NodeVersion = %d, want 20", opts.NodeVersion)
	}
	if !opts.InstallNode || opts.InstallBun || !opts.InstallDocker {
		t.Errorf("runtime flags = %+v, want node=true bun=false docker=true", opts)
	}
	if len(opts.AITools) != 2 || opts.AITools[0] != AIToolClaudeCode || opts.AITools[1] != AIToolOllama {
		t.Errorf("AITools = %v, want [claude-code ollama]", opts.AITools)
	}

	// Mutating the returned slice must not alias the caller's slice.
	opts.AITools[0] = "tampered"
	if r.AITools[0] != AIToolClaudeCode {
		t.Errorf("ToProvisionOptions aliased AITools slice")
	}
}

func TestWizardResult_ToConfig_Tools(t *testing.T) {
	r := WizardResult{
		TrustLevel:    TrustCautious,
		ResourceLevel: ResourceStandard,
		InstallNode:   true,
		InstallBun:    true,
		InstallDocker: false,
		AITools:       []string{AIToolGemini},
	}

	cfg := r.ToConfig("node")

	if !cfg.Tools.Node || !cfg.Tools.Bun || cfg.Tools.Docker {
		t.Errorf("Tools runtime flags wrong: %+v", cfg.Tools)
	}
	if len(cfg.Tools.AITools) != 1 || cfg.Tools.AITools[0] != AIToolGemini {
		t.Errorf("Tools.AITools = %v, want [gemini]", cfg.Tools.AITools)
	}
}

func TestNetworkLevels(t *testing.T) {
	levels := NetworkLevels()
	if len(levels) != 3 {
		t.Fatalf("NetworkLevels() returned %d levels, want 3", len(levels))
	}

	// Check ongoing has warning
	for _, level := range levels {
		if level.Level == NetworkOngoing && level.Warning == "" {
			t.Errorf("NetworkLevels() ongoing should have a warning")
		}
	}
}
