package integration

import (
	"strings"
	"testing"

	"github.com/muneebs/airlock/internal/api"
)

func TestRunCommand(t *testing.T) {
	h := newHarness(t)
	h.createVMFiles(t, "run-test")

	spec := api.SandboxSpec{
		Name:    "run-test",
		Profile: "dev",
		CPU:     intPtr(2),
	}

	_, err := h.Manager.Create(h.ctx(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	h.resetCalls()

	output, err := h.Manager.Run(h.ctx(), "run-test", []string{"echo", "hello"})
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	if output == "" {
		t.Error("expected non-empty output from Run()")
	}

	foundShell := false
	for _, c := range h.calls() {
		if strings.Contains(c, "shell") && strings.Contains(c, "run-test") {
			foundShell = true
		}
	}
	if !foundShell {
		t.Error("expected limactl shell call for running command")
	}
}

func TestRunEmptyCommandFails(t *testing.T) {
	h := newHarness(t)
	h.createVMFiles(t, "run-empty")

	spec := api.SandboxSpec{
		Name:    "run-empty",
		Profile: "dev",
		CPU:     intPtr(2),
	}

	_, err := h.Manager.Create(h.ctx(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	_, err = h.Manager.Run(h.ctx(), "run-empty", []string{})
	if err == nil {
		t.Error("expected error for empty command")
	}
}

func TestRunNonexistentSandbox(t *testing.T) {
	h := newHarness(t)

	_, err := h.Manager.Run(h.ctx(), "nonexistent", []string{"echo", "hi"})
	if err == nil {
		t.Error("expected error running in nonexistent sandbox")
	}
}

func TestRunStartsStoppedSandbox(t *testing.T) {
	h := newHarness(t)
	h.createVMFiles(t, "restart-run")

	spec := api.SandboxSpec{
		Name:    "restart-run",
		Profile: "dev",
		CPU:     intPtr(2),
	}

	_, err := h.Manager.Create(h.ctx(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if err := h.Manager.Stop(h.ctx(), "restart-run"); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}

	h.resetCalls()

	_, err = h.Manager.Run(h.ctx(), "restart-run", []string{"ls"})
	if err != nil {
		t.Fatalf("Run() after stop error: %v", err)
	}

	foundStart := false
	for _, c := range h.calls() {
		if strings.HasPrefix(c, "start ") && strings.Contains(c, "restart-run") {
			foundStart = true
		}
	}
	if !foundStart {
		t.Error("expected limactl start call when running in stopped sandbox")
	}
}
