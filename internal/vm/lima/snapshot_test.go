package lima

import (
	"context"
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

func TestSnapshotCleanMasksPermissions(t *testing.T) {
	dir := t.TempDir()
	vmDir := filepath.Join(dir, "test-vm")
	os.MkdirAll(vmDir, 0755)
	os.WriteFile(filepath.Join(vmDir, "suid-file"), []byte("suid"), 04755)
	os.WriteFile(filepath.Join(vmDir, "world-writable"), []byte("ww"), 0777)
	os.WriteFile(filepath.Join(vmDir, "normal-file"), []byte("normal"), 0644)

	p := NewLimaProviderWithPaths("/bin/true", dir)

	err := p.SnapshotClean(nil, "test-vm")
	if err != nil {
		t.Fatalf("SnapshotClean() error: %v", err)
	}

	cleanDir := filepath.Join(dir, "test-vm-clean")

	suidInfo, err := os.Stat(filepath.Join(cleanDir, "suid-file"))
	if err != nil {
		t.Fatalf("stat suid-file: %v", err)
	}
	if suidInfo.Mode()&04000 != 0 {
		t.Errorf("SUID bit should be stripped from suid-file, got mode %o", suidInfo.Mode())
	}
	if suidInfo.Mode().Perm() != 0755 {
		t.Errorf("expected mode 0755 for suid-file, got %o", suidInfo.Mode().Perm())
	}

	wwInfo, err := os.Stat(filepath.Join(cleanDir, "world-writable"))
	if err != nil {
		t.Fatalf("stat world-writable: %v", err)
	}
	if wwInfo.Mode().Perm()&0002 != 0 {
		t.Errorf("world-write bit should be stripped, got mode %o", wwInfo.Mode().Perm())
	}

	normalInfo, err := os.Stat(filepath.Join(cleanDir, "normal-file"))
	if err != nil {
		t.Fatalf("stat normal-file: %v", err)
	}
	if normalInfo.Mode().Perm() != 0644&0755 {
		t.Errorf("expected normal file mode masked to %o, got %o", 0644&0755, normalInfo.Mode().Perm())
	}
}

func TestRestoreCleanMasksPermissions(t *testing.T) {
	dir := t.TempDir()

	cleanDir := filepath.Join(dir, "test-vm-clean")
	os.MkdirAll(cleanDir, 0755)
	os.WriteFile(filepath.Join(cleanDir, "config"), []byte("clean"), 0644)

	vmDir := filepath.Join(dir, "test-vm")
	os.MkdirAll(vmDir, 0755)

	p := NewLimaProviderWithPaths("/bin/true", dir)

	err := p.RestoreClean(nil, "test-vm")
	if err != nil {
		t.Fatalf("RestoreClean() error: %v", err)
	}

	restoredInfo, err := os.Stat(filepath.Join(vmDir, "config"))
	if err != nil {
		t.Fatalf("stat restored config: %v", err)
	}
	if restoredInfo.Mode().Perm() != 0644&0755 {
		t.Errorf("expected restored file mode %o, got %o", 0644&0755, restoredInfo.Mode().Perm())
	}
}

func TestHasCleanSnapshot(t *testing.T) {
	dir := t.TempDir()
	p := NewLimaProviderWithPaths("/bin/true", dir)

	ok, err := p.HasCleanSnapshot(context.Background(), "test-vm")
	if err != nil {
		t.Fatalf("HasCleanSnapshot error: %v", err)
	}
	if ok {
		t.Error("expected no clean snapshot initially")
	}

	os.MkdirAll(filepath.Join(dir, "test-vm-clean"), 0755)
	ok, err = p.HasCleanSnapshot(context.Background(), "test-vm")
	if err != nil {
		t.Fatalf("HasCleanSnapshot error after creating dir: %v", err)
	}
	if !ok {
		t.Error("expected clean snapshot to exist after creating dir")
	}
}
