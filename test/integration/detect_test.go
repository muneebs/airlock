package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/muneebs/airlock/internal/api"
)

func TestDetectNodeProject(t *testing.T) {
	h := newHarness(t)
	projectDir := filepath.Join(h.tmpDir, "nodeproj")
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte("{}"), 0644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	h.createVMFiles(t, "node-detect")

	spec := api.SandboxSpec{
		Name:    "node-detect",
		Source:  projectDir,
		Profile: "dev",
		CPU:     intPtr(2),
	}

	info, err := h.Manager.Create(h.ctx(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if info.Runtime != string(api.RuntimeNode) {
		t.Errorf("expected runtime node, got %s", info.Runtime)
	}
}

func TestDetectGoProject(t *testing.T) {
	h := newHarness(t)
	projectDir := filepath.Join(h.tmpDir, "goproj")
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "go.mod"), []byte("module example.com/test\ngo 1.23\n"), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	h.createVMFiles(t, "go-detect")

	spec := api.SandboxSpec{
		Name:    "go-detect",
		Source:  projectDir,
		Profile: "dev",
		CPU:     intPtr(2),
	}

	info, err := h.Manager.Create(h.ctx(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if info.Runtime != string(api.RuntimeGo) {
		t.Errorf("expected runtime go, got %s", info.Runtime)
	}
}

func TestDetectExplicitRuntimeOverrides(t *testing.T) {
	h := newHarness(t)
	projectDir := filepath.Join(h.tmpDir, "overrideme")
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "package.json"), []byte("{}"), 0644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	h.createVMFiles(t, "override-detect")

	spec := api.SandboxSpec{
		Name:    "override-detect",
		Source:  projectDir,
		Runtime: "python",
		Profile: "dev",
		CPU:     intPtr(2),
	}

	info, err := h.Manager.Create(h.ctx(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if info.Runtime != string(api.RuntimePython) {
		t.Errorf("expected runtime python (explicit override), got %s", info.Runtime)
	}
}

func TestDetectNoMarkersYieldsUnknown(t *testing.T) {
	h := newHarness(t)
	projectDir := filepath.Join(h.tmpDir, "emptyproj")
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}

	h.createVMFiles(t, "unknown-detect")

	spec := api.SandboxSpec{
		Name:    "unknown-detect",
		Source:  projectDir,
		Profile: "dev",
		CPU:     intPtr(2),
	}

	info, err := h.Manager.Create(h.ctx(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if info.Runtime != string(api.RuntimeUnknown) {
		t.Errorf("expected runtime unknown for empty project, got %s", info.Runtime)
	}
}

func TestDetectDockerCompose(t *testing.T) {
	h := newHarness(t)
	projectDir := filepath.Join(h.tmpDir, "composeproj")
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, "compose.yml"), []byte("services:\n  app:\n    image: nginx\n"), 0644); err != nil {
		t.Fatalf("write compose.yml: %v", err)
	}

	h.createVMFiles(t, "compose-detect")

	spec := api.SandboxSpec{
		Name:    "compose-detect",
		Source:  projectDir,
		Profile: "dev",
		CPU:     intPtr(2),
	}

	info, err := h.Manager.Create(h.ctx(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if info.Runtime != string(api.RuntimeCompose) {
		t.Errorf("expected runtime compose, got %s", info.Runtime)
	}
}
