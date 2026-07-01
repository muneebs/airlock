package lima

import (
	"strings"
	"testing"

	"github.com/muneebs/airlock/internal/api"
)

// ProvisionSteps only constructs the step list; the fake limactl path is never
// invoked because these tests inspect step labels rather than running the steps.

// TestProvisionStepsSurfacesUnknownAITool guards the fix for silently dropped
// AI tools: an unrecognized name (a typo, or a tool not in the registry) must
// produce a visible step naming it, instead of a setup that looks clean while
// the tool was never installed.
func TestProvisionStepsSurfacesUnknownAITool(t *testing.T) {
	p := NewLimaProviderWithPaths("/usr/bin/true", "/tmp/airlock-test-lima", "")

	steps := p.ProvisionSteps("test-vm", api.ProvisionOptions{
		AITools: []string{"claude-code", "hermes", "multica"},
	})

	var labels []string
	for _, s := range steps {
		labels = append(labels, s.Label)
	}
	joined := strings.Join(labels, "\n")

	if !strings.Contains(joined, "Installing Claude Code") {
		t.Errorf("expected a Claude Code install step, got labels:\n%s", joined)
	}
	if !strings.Contains(joined, "hermes") || !strings.Contains(joined, "multica") {
		t.Errorf("expected unrecognized tools to be surfaced in a step label, got:\n%s", joined)
	}
}

// TestProvisionStepsAllKnownToolsNoWarning verifies the warning step only
// appears when there is actually an unrecognized tool.
func TestProvisionStepsAllKnownToolsNoWarning(t *testing.T) {
	p := NewLimaProviderWithPaths("/usr/bin/true", "/tmp/airlock-test-lima", "")

	steps := p.ProvisionSteps("test-vm", api.ProvisionOptions{
		AITools: []string{"claude-code"},
	})

	for _, s := range steps {
		if strings.Contains(s.Label, "unrecognized") {
			t.Errorf("did not expect an unrecognized-tools step, got label: %q", s.Label)
		}
	}
}

// TestKnownAIToolsSorted confirms the helper returns the registry keys sorted,
// so user-facing messages are stable.
func TestKnownAIToolsSorted(t *testing.T) {
	tools := knownAITools()
	if len(tools) == 0 {
		t.Fatal("expected at least one registered AI tool")
	}
	for i := 1; i < len(tools); i++ {
		if tools[i-1] > tools[i] {
			t.Errorf("knownAITools() not sorted: %v", tools)
		}
	}
	var hasClaude bool
	for _, tool := range tools {
		if tool == "claude-code" {
			hasClaude = true
		}
	}
	if !hasClaude {
		t.Errorf("expected claude-code in known tools, got %v", tools)
	}
}
