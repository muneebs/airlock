package lima

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotClean(t *testing.T) {
	dir := t.TempDir()
	vmDir := filepath.Join(dir, "test-vm")
	os.MkdirAll(filepath.Join(vmDir, "sub"), 0755)
	os.WriteFile(filepath.Join(vmDir, "lima.yaml"), []byte("vmType: vz"), 0644)
	os.WriteFile(filepath.Join(vmDir, "sub", "data"), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(vmDir, "runtime.sock"), []byte(""), 0644)

	p := NewLimaProviderWithPaths("/bin/true", dir)

	err := p.SnapshotClean(nil, "test-vm")
	if err != nil {
		t.Fatalf("SnapshotClean() error: %v", err)
	}

	cleanDir := filepath.Join(dir, "test-vm-clean")
	if _, err := os.Stat(cleanDir); err != nil {
		t.Fatalf("clean dir not created: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(cleanDir, "lima.yaml"))
	if err != nil || string(data) != "vmType: vz" {
		t.Errorf("lima.yaml not copied correctly")
	}

	data, err = os.ReadFile(filepath.Join(cleanDir, "sub", "data"))
	if err != nil || string(data) != "hello" {
		t.Errorf("sub/data not copied correctly")
	}

	if _, err := os.Stat(filepath.Join(cleanDir, "runtime.sock")); err == nil {
		t.Error("socket files should be excluded from snapshot")
	}
}

func TestRestoreClean(t *testing.T) {
	dir := t.TempDir()

	cleanDir := filepath.Join(dir, "test-vm-clean")
	os.MkdirAll(cleanDir, 0755)
	os.WriteFile(filepath.Join(cleanDir, "lima.yaml"), []byte("vmType: vz"), 0644)

	vmDir := filepath.Join(dir, "test-vm")
	os.MkdirAll(vmDir, 0755)
	os.WriteFile(filepath.Join(vmDir, "lima.yaml"), []byte("dirty"), 0644)

	p := NewLimaProviderWithPaths("/bin/true", dir)

	err := p.RestoreClean(nil, "test-vm")
	if err != nil {
		t.Fatalf("RestoreClean() error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(vmDir, "lima.yaml"))
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(data) != "vmType: vz" {
		t.Errorf("expected clean content, got: %s", string(data))
	}
}

func TestHasCleanSnapshot(t *testing.T) {
	dir := t.TempDir()
	p := NewLimaProviderWithPaths("/bin/true", dir)

	if p.HasCleanSnapshot("test-vm") {
		t.Error("expected no clean snapshot initially")
	}

	os.MkdirAll(filepath.Join(dir, "test-vm-clean"), 0755)
	if !p.HasCleanSnapshot("test-vm") {
		t.Error("expected clean snapshot to exist after creating dir")
	}
}
