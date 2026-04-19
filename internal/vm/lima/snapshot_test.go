package lima

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/muneebs/airlock/internal/api"
)

func TestSnapshotClean(t *testing.T) {
	dir := t.TempDir()
	snapDir := t.TempDir()
	vmDir := filepath.Join(dir, "test-vm")
	os.MkdirAll(filepath.Join(vmDir, "sub"), 0755)
	os.WriteFile(filepath.Join(vmDir, "lima.yaml"), []byte("vmType: vz"), 0644)
	os.WriteFile(filepath.Join(vmDir, "sub", "data"), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(vmDir, "runtime.sock"), []byte(""), 0644)

	p := NewLimaProviderWithPaths("/bin/true", dir, snapDir)

	if err := p.SnapshotClean(nil, "test-vm"); err != nil {
		t.Fatalf("SnapshotClean() error: %v", err)
	}

	cleanDir := filepath.Join(snapDir, "test-vm")
	if _, err := os.Stat(cleanDir); err != nil {
		t.Fatalf("clean dir not created at snapshot path: %v", err)
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

	// Snapshot must NOT live inside limaDir — that was the whole point of
	// moving it (Lima was listing it as an extra VM).
	legacy := filepath.Join(dir, "test-vm-clean")
	if _, err := os.Stat(legacy); err == nil {
		t.Errorf("snapshot leaked into limaDir at %s", legacy)
	}
}

// TestSnapshotClean_RemovesLegacy verifies that calling SnapshotClean after
// an upgrade deletes the pre-migration snapshot from inside limaDir so the
// user's `limactl list` output is no longer polluted.
func TestSnapshotClean_RemovesLegacy(t *testing.T) {
	dir := t.TempDir()
	snapDir := t.TempDir()
	vmDir := filepath.Join(dir, "test-vm")
	os.MkdirAll(vmDir, 0755)
	os.WriteFile(filepath.Join(vmDir, "lima.yaml"), []byte("x"), 0644)

	legacy := filepath.Join(dir, "test-vm-clean")
	os.MkdirAll(legacy, 0755)
	os.WriteFile(filepath.Join(legacy, "lima.yaml"), []byte("old"), 0644)

	p := NewLimaProviderWithPaths("/bin/true", dir, snapDir)
	if err := p.SnapshotClean(nil, "test-vm"); err != nil {
		t.Fatalf("SnapshotClean() error: %v", err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Errorf("legacy snapshot should be removed, stat err = %v", err)
	}
}

func TestRestoreClean(t *testing.T) {
	dir := t.TempDir()
	snapDir := t.TempDir()

	cleanDir := filepath.Join(snapDir, "test-vm")
	os.MkdirAll(cleanDir, 0755)
	os.WriteFile(filepath.Join(cleanDir, "lima.yaml"), []byte("vmType: vz"), 0644)

	vmDir := filepath.Join(dir, "test-vm")
	os.MkdirAll(vmDir, 0755)
	os.WriteFile(filepath.Join(vmDir, "lima.yaml"), []byte("dirty"), 0644)

	p := NewLimaProviderWithPaths("/bin/true", dir, snapDir)

	if err := p.RestoreClean(nil, "test-vm"); err != nil {
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

// TestRestoreClean_LegacyFallback ensures users with pre-migration snapshots
// (only the in-limaDir copy) can still reset without re-running setup.
func TestRestoreClean_LegacyFallback(t *testing.T) {
	dir := t.TempDir()
	snapDir := t.TempDir()

	legacy := filepath.Join(dir, "test-vm-clean")
	os.MkdirAll(legacy, 0755)
	os.WriteFile(filepath.Join(legacy, "lima.yaml"), []byte("legacy-clean"), 0644)

	vmDir := filepath.Join(dir, "test-vm")
	os.MkdirAll(vmDir, 0755)
	os.WriteFile(filepath.Join(vmDir, "lima.yaml"), []byte("dirty"), 0644)

	p := NewLimaProviderWithPaths("/bin/true", dir, snapDir)

	if err := p.RestoreClean(nil, "test-vm"); err != nil {
		t.Fatalf("RestoreClean() error: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(vmDir, "lima.yaml"))
	if string(data) != "legacy-clean" {
		t.Errorf("expected legacy content, got: %s", string(data))
	}
}

func TestSnapshotCleanMasksPermissions(t *testing.T) {
	dir := t.TempDir()
	snapDir := t.TempDir()
	vmDir := filepath.Join(dir, "test-vm")
	os.MkdirAll(vmDir, 0755)
	os.WriteFile(filepath.Join(vmDir, "suid-file"), []byte("suid"), 04755)
	os.WriteFile(filepath.Join(vmDir, "world-writable"), []byte("ww"), 0777)
	os.WriteFile(filepath.Join(vmDir, "normal-file"), []byte("normal"), 0644)

	p := NewLimaProviderWithPaths("/bin/true", dir, snapDir)

	err := p.SnapshotClean(nil, "test-vm")
	if err != nil {
		t.Fatalf("SnapshotClean() error: %v", err)
	}

	cleanDir := filepath.Join(snapDir, "test-vm")

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
	snapDir := t.TempDir()

	cleanDir := filepath.Join(snapDir, "test-vm")
	os.MkdirAll(cleanDir, 0755)
	os.WriteFile(filepath.Join(cleanDir, "config"), []byte("clean"), 0644)

	vmDir := filepath.Join(dir, "test-vm")
	os.MkdirAll(vmDir, 0755)

	p := NewLimaProviderWithPaths("/bin/true", dir, snapDir)

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

func stepLabels(steps []api.ProvisionStep) []string {
	out := make([]string, len(steps))
	for i, s := range steps {
		out[i] = s.Label
	}
	return out
}

func hasPrefix(labels []string, prefix string) bool {
	for _, l := range labels {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

func TestProvisionSteps_BaselineOnly(t *testing.T) {
	p := NewLimaProviderWithPaths("/bin/true", t.TempDir(), "")

	steps := p.ProvisionSteps("vm", api.ProvisionOptions{})
	labels := stepLabels(steps)

	// Baseline steps are always present.
	for _, want := range []string{"Installing system packages", "Creating airlock user", "Preparing airlock home"} {
		if !hasPrefix(labels, want) {
			t.Errorf("missing baseline step %q in %v", want, labels)
		}
	}
	// Nothing optional should be installed.
	for _, forbidden := range []string{"Installing Node.js", "Installing pnpm", "Configuring npm prefix", "Installing Bun", "Installing Docker", "Installing Claude Code", "Installing Gemini CLI", "Installing Codex CLI", "Installing OpenCode", "Installing Ollama"} {
		if hasPrefix(labels, forbidden) {
			t.Errorf("unexpected optional step %q in %v", forbidden, labels)
		}
	}
}

func TestProvisionSteps_NodeEnabled(t *testing.T) {
	p := NewLimaProviderWithPaths("/bin/true", t.TempDir(), "")

	steps := p.ProvisionSteps("vm", api.ProvisionOptions{InstallNode: true, NodeVersion: 20})
	labels := stepLabels(steps)

	if !hasPrefix(labels, "Installing Node.js 20") {
		t.Errorf("want Node.js 20 step, got %v", labels)
	}
	for _, want := range []string{"Installing pnpm", "Configuring npm prefix"} {
		if !hasPrefix(labels, want) {
			t.Errorf("missing %q in %v", want, labels)
		}
	}
}

func TestProvisionSteps_AIToolForcesNode(t *testing.T) {
	p := NewLimaProviderWithPaths("/bin/true", t.TempDir(), "")

	// Claude Code is npm-based, so Node must auto-enable even when InstallNode is false.
	steps := p.ProvisionSteps("vm", api.ProvisionOptions{AITools: []string{"claude-code"}})
	labels := stepLabels(steps)

	if !hasPrefix(labels, "Installing Node.js") {
		t.Errorf("npm-based AI tool should force Node.js: %v", labels)
	}
	if !hasPrefix(labels, "Installing Claude Code") {
		t.Errorf("missing Claude Code step: %v", labels)
	}
}

func TestProvisionSteps_AllOptions(t *testing.T) {
	p := NewLimaProviderWithPaths("/bin/true", t.TempDir(), "")

	steps := p.ProvisionSteps("vm", api.ProvisionOptions{
		NodeVersion:   22,
		InstallNode:   true,
		InstallBun:    true,
		InstallDocker: true,
		AITools:       []string{"claude-code", "gemini", "codex", "opencode", "ollama"},
	})
	labels := stepLabels(steps)

	for _, want := range []string{
		"Installing Bun",
		"Installing Docker",
		"Installing Claude Code",
		"Installing Gemini CLI",
		"Installing Codex CLI",
		"Installing OpenCode",
		"Installing Ollama",
	} {
		if !hasPrefix(labels, want) {
			t.Errorf("missing %q in %v", want, labels)
		}
	}
}

func TestProvisionSteps_UnknownAIToolIgnored(t *testing.T) {
	p := NewLimaProviderWithPaths("/bin/true", t.TempDir(), "")

	steps := p.ProvisionSteps("vm", api.ProvisionOptions{AITools: []string{"unknown-tool"}})
	labels := stepLabels(steps)

	for _, l := range labels {
		if strings.Contains(l, "unknown-tool") {
			t.Errorf("unknown AI tool should be ignored, got label %q", l)
		}
	}
	// An unknown tool is not npm-based, so Node should NOT be forced on.
	if hasPrefix(labels, "Installing Node.js") {
		t.Errorf("unknown tool should not force Node.js: %v", labels)
	}
}

func TestHasCleanSnapshot(t *testing.T) {
	dir := t.TempDir()
	snapDir := t.TempDir()
	p := NewLimaProviderWithPaths("/bin/true", dir, snapDir)

	ok, err := p.HasCleanSnapshot(context.Background(), "test-vm")
	if err != nil {
		t.Fatalf("HasCleanSnapshot error: %v", err)
	}
	if ok {
		t.Error("expected no clean snapshot initially")
	}

	// Current location: snapshotDir/<name>
	os.MkdirAll(filepath.Join(snapDir, "test-vm"), 0755)
	ok, err = p.HasCleanSnapshot(context.Background(), "test-vm")
	if err != nil {
		t.Fatalf("HasCleanSnapshot error: %v", err)
	}
	if !ok {
		t.Error("expected clean snapshot to exist at new location")
	}
}

// TestHasCleanSnapshot_LegacyOnly confirms HasCleanSnapshot recognises the
// pre-migration in-limaDir snapshot so upgraded users see reset as available.
func TestHasCleanSnapshot_LegacyOnly(t *testing.T) {
	dir := t.TempDir()
	snapDir := t.TempDir()
	p := NewLimaProviderWithPaths("/bin/true", dir, snapDir)

	os.MkdirAll(filepath.Join(dir, "test-vm-clean"), 0755)
	ok, err := p.HasCleanSnapshot(context.Background(), "test-vm")
	if err != nil {
		t.Fatalf("HasCleanSnapshot error: %v", err)
	}
	if !ok {
		t.Error("legacy snapshot path should be detected")
	}
}
