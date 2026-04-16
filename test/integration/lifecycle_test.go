package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/muneebs/airlock/internal/api"
)

func TestFullLifecycle(t *testing.T) {
	h := newHarness(t)
	h.createVMFiles(t, "lifecycle")

	spec := api.SandboxSpec{
		Name:    "lifecycle",
		Profile: "cautious",
		CPU:     intPtr(2),
	}

	info, err := h.Manager.Create(h.ctx(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	if info.State != api.StateRunning {
		t.Errorf("expected running, got %s", info.State)
	}

	info, err = h.Manager.Status(h.ctx(), "lifecycle")
	if err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if info.State != api.StateRunning {
		t.Errorf("expected running, got %s", info.State)
	}

	sandboxes, err := h.Manager.List(h.ctx())
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(sandboxes) != 1 {
		t.Fatalf("expected 1 sandbox, got %d", len(sandboxes))
	}

	if err := h.Manager.Stop(h.ctx(), "lifecycle"); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}

	info, err = h.Manager.Status(h.ctx(), "lifecycle")
	if err != nil {
		t.Fatalf("Status() after stop error: %v", err)
	}
	if info.State != api.StateStopped {
		t.Errorf("expected stopped, got %s", info.State)
	}

	if err := h.Manager.Start(h.ctx(), "lifecycle"); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	info, err = h.Manager.Status(h.ctx(), "lifecycle")
	if err != nil {
		t.Fatalf("Status() after start error: %v", err)
	}
	if info.State != api.StateRunning {
		t.Errorf("expected running after start, got %s", info.State)
	}

	if err := h.Manager.Destroy(h.ctx(), "lifecycle"); err != nil {
		t.Fatalf("Destroy() error: %v", err)
	}

	_, err = h.Manager.Status(h.ctx(), "lifecycle")
	if err == nil {
		t.Error("expected error after destroy")
	}
}

func TestStopAlreadyStopped(t *testing.T) {
	h := newHarness(t)
	h.createVMFiles(t, "double-stop")

	spec := api.SandboxSpec{
		Name:    "double-stop",
		Profile: "cautious",
		CPU:     intPtr(2),
	}

	_, err := h.Manager.Create(h.ctx(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	t.Cleanup(func() { _ = h.Manager.Destroy(h.ctx(), "double-stop") })

	if err := h.Manager.Stop(h.ctx(), "double-stop"); err != nil {
		t.Fatalf("first Stop() error: %v", err)
	}

	if err := h.Manager.Stop(h.ctx(), "double-stop"); err != nil {
		t.Fatalf("second Stop() error: %v", err)
	}
}

func TestDestroyRemovesMounts(t *testing.T) {
	h := newHarness(t)
	h.createVMFiles(t, "mount-del")

	projectDir := filepath.Join(h.tmpDir, "project")
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}

	spec := api.SandboxSpec{
		Name:    "mount-del",
		Source:  projectDir,
		Profile: "dev",
		CPU:     intPtr(2),
	}

	_, err := h.Manager.Create(h.ctx(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	mounts, err := h.Mounts.List(h.ctx(), "mount-del")
	if err != nil {
		t.Fatalf("Mounts.List() error: %v", err)
	}
	if len(mounts) == 0 {
		t.Error("expected mount to be registered")
	}

	if err := h.Manager.Destroy(h.ctx(), "mount-del"); err != nil {
		t.Fatalf("Destroy() error: %v", err)
	}

	mounts, err = h.Mounts.List(h.ctx(), "mount-del")
	if err == nil && len(mounts) > 0 {
		t.Error("expected mount to be unregistered after destroy")
	}
}
