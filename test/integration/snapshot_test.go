package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/muneebs/airlock/internal/api"
)

func TestSnapshotAndReset(t *testing.T) {
	h := newHarness(t)
	h.createVMFiles(t, "snap-test")

	cleanDir := h.snapshotPath("snap-test")
	if err := os.MkdirAll(cleanDir, 0755); err != nil {
		t.Fatalf("mkdir clean dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cleanDir, "lima.yaml"), []byte("clean: true\n"), 0600); err != nil {
		t.Fatalf("write clean file: %v", err)
	}

	spec := api.SandboxSpec{
		Name:    "snap-test",
		Profile: "cautious",
		CPU:     intPtr(2),
	}

	_, err := h.Manager.Create(h.ctx(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	hasSnapshot, err := h.Provider.HasCleanSnapshot(h.ctx(), "snap-test")
	if err != nil {
		t.Fatalf("HasCleanSnapshot() error: %v", err)
	}
	if !hasSnapshot {
		t.Error("expected clean snapshot to exist after manual setup")
	}

	if err := h.Manager.Reset(h.ctx(), "snap-test"); err != nil {
		t.Fatalf("Reset() error: %v", err)
	}

	info, err := h.Manager.Status(h.ctx(), "snap-test")
	if err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if info.State != api.StateRunning {
		t.Errorf("expected state running after reset, got %s", info.State)
	}
}

func TestResetWithoutSnapshotFails(t *testing.T) {
	h := newHarness(t)
	h.createVMFiles(t, "no-snap")

	spec := api.SandboxSpec{
		Name:    "no-snap",
		Profile: "cautious",
		CPU:     intPtr(2),
	}

	_, err := h.Manager.Create(h.ctx(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if err := h.Manager.Stop(h.ctx(), "no-snap"); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}

	err = h.Manager.Reset(h.ctx(), "no-snap")
	if err == nil {
		t.Error("expected error resetting without snapshot")
	}
}

func TestSnapshotCleanCapturesVMState(t *testing.T) {
	h := newHarness(t)

	vmDir := filepath.Join(h.limaDir, "snap-capture")
	if err := os.MkdirAll(vmDir, 0755); err != nil {
		t.Fatalf("mkdir vm dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(vmDir, "test.txt"), []byte("hello"), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	sockPath := filepath.Join(vmDir, "lima.sock")
	if err := os.WriteFile(sockPath, []byte(""), 0644); err != nil {
		t.Fatalf("write sock file: %v", err)
	}

	if err := h.Provider.SnapshotClean(h.ctx(), "snap-capture"); err != nil {
		t.Fatalf("SnapshotClean() error: %v", err)
	}

	cleanDir := h.snapshotPath("snap-capture")
	data, err := os.ReadFile(filepath.Join(cleanDir, "test.txt"))
	if err != nil {
		t.Fatalf("read clean test.txt: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("expected 'hello', got %q", string(data))
	}

	if _, err := os.Stat(filepath.Join(cleanDir, "lima.sock")); !os.IsNotExist(err) {
		t.Error("expected .sock files to be excluded from clean snapshot")
	}
}

func TestRestoreCleanOverwritesDirtyState(t *testing.T) {
	h := newHarness(t)

	vmDir := filepath.Join(h.limaDir, "snap-restore")
	if err := os.MkdirAll(vmDir, 0755); err != nil {
		t.Fatalf("mkdir vm dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(vmDir, "data.txt"), []byte("dirty"), 0644); err != nil {
		t.Fatalf("write dirty file: %v", err)
	}

	if err := h.Provider.SnapshotClean(h.ctx(), "snap-restore"); err != nil {
		t.Fatalf("SnapshotClean() error: %v", err)
	}

	if err := os.WriteFile(filepath.Join(vmDir, "data.txt"), []byte("modified"), 0644); err != nil {
		t.Fatalf("write modified file: %v", err)
	}

	if err := h.Provider.RestoreClean(h.ctx(), "snap-restore"); err != nil {
		t.Fatalf("RestoreClean() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(vmDir, "data.txt"))
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(data) != "dirty" {
		t.Errorf("expected 'dirty' after restore, got %q", string(data))
	}
}
