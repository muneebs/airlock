package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()

	if cfg.VM.CPU != 2 {
		t.Errorf("expected CPU 2, got %d", cfg.VM.CPU)
	}
	if cfg.VM.Memory != "4GiB" {
		t.Errorf("expected Memory 4GiB, got %s", cfg.VM.Memory)
	}
	if cfg.VM.Disk != "20GiB" {
		t.Errorf("expected Disk 20GiB, got %s", cfg.VM.Disk)
	}
	if cfg.VM.NodeVersion != 22 {
		t.Errorf("expected NodeVersion 22, got %d", cfg.VM.NodeVersion)
	}
	if cfg.Dev.Ports != "3000:9999" {
		t.Errorf("expected Ports 3000:9999, got %s", cfg.Dev.Ports)
	}
	if cfg.Security.Profile != "cautious" {
		t.Errorf("expected default profile cautious, got %s", cfg.Security.Profile)
	}
}

func TestLoadTOML(t *testing.T) {
	dir := t.TempDir()
	tomlContent := `
[vm]
cpu = 4
memory = "8GiB"
disk = "40GiB"
node_version = 20

[dev]
ports = "8080:8080"
command = "pnpm dev"

[runtime]
type = "node"
docker = true

[security]
profile = "dev"

[[mounts]]
path = "./api"
writable = false

[[mounts]]
path = "./shared"
writable = true
inotify = true
`
	err := os.WriteFile(filepath.Join(dir, "airlock.toml"), []byte(tomlContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.VM.CPU != 4 {
		t.Errorf("expected CPU 4, got %d", cfg.VM.CPU)
	}
	if cfg.VM.Memory != "8GiB" {
		t.Errorf("expected Memory 8GiB, got %s", cfg.VM.Memory)
	}
	if cfg.Dev.Ports != "8080:8080" {
		t.Errorf("expected Ports 8080:8080, got %s", cfg.Dev.Ports)
	}
	if cfg.Dev.Command != "pnpm dev" {
		t.Errorf("expected Command pnpm dev, got %s", cfg.Dev.Command)
	}
	if cfg.Runtime.Type != "node" {
		t.Errorf("expected runtime type node, got %s", cfg.Runtime.Type)
	}
	if !cfg.Runtime.Docker {
		t.Error("expected docker true")
	}
	if cfg.Security.Profile != "dev" {
		t.Errorf("expected profile dev, got %s", cfg.Security.Profile)
	}
	if len(cfg.Mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(cfg.Mounts))
	}
	if cfg.Mounts[0].Path != "./api" {
		t.Errorf("expected mount path ./api, got %s", cfg.Mounts[0].Path)
	}
	if *cfg.Mounts[0].Writable {
		t.Error("expected first mount writable=false")
	}
	if !*cfg.Mounts[1].Writable {
		t.Error("expected second mount writable=true")
	}
	if !cfg.Mounts[1].Inotify {
		t.Error("expected second mount inotify=true")
	}
}

func TestLoadYAML(t *testing.T) {
	dir := t.TempDir()
	yamlContent := `vm:
  cpu: 4
  memory: "8GiB"
  disk: "40GiB"
  node_version: 20
dev:
  ports: "8080:8080"
  command: "pnpm dev"
runtime:
  type: "go"
  docker: true
security:
  profile: "strict"
mounts:
  - path: "./api"
    writable: false
`
	err := os.WriteFile(filepath.Join(dir, "airlock.yaml"), []byte(yamlContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.VM.CPU != 4 {
		t.Errorf("expected CPU 4, got %d", cfg.VM.CPU)
	}
	if cfg.Runtime.Type != "go" {
		t.Errorf("expected runtime go, got %s", cfg.Runtime.Type)
	}
	if cfg.Security.Profile != "strict" {
		t.Errorf("expected profile strict, got %s", cfg.Security.Profile)
	}
	if len(cfg.Mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(cfg.Mounts))
	}
	if cfg.Mounts[0].Path != "./api" {
		t.Errorf("expected mount path ./api, got %s", cfg.Mounts[0].Path)
	}
}

func TestMountDefaultIsReadOnly(t *testing.T) {
	dir := t.TempDir()
	tomlContent := `
[[mounts]]
path = "./data"
`
	err := os.WriteFile(filepath.Join(dir, "airlock.toml"), []byte(tomlContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if len(cfg.Mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(cfg.Mounts))
	}
	if cfg.Mounts[0].Writable == nil {
		t.Fatal("expected Writable to be set by mergeWithDefaults, got nil")
	}
	if *cfg.Mounts[0].Writable {
		t.Error("expected mount to default to read-only (writable=false)")
	}
}

func TestLoadNoConfig(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() with no config should not error: %v", err)
	}

	defaults := Defaults()
	if cfg.VM.CPU != defaults.VM.CPU {
		t.Errorf("expected default CPU %d, got %d", defaults.VM.CPU, cfg.VM.CPU)
	}
	if cfg.Security.Profile != defaults.Security.Profile {
		t.Errorf("expected default profile %s, got %s", defaults.Security.Profile, cfg.Security.Profile)
	}
}

func TestLoadMergesWithDefaults(t *testing.T) {
	dir := t.TempDir()
	tomlContent := `
[vm]
cpu = 8
`
	err := os.WriteFile(filepath.Join(dir, "airlock.toml"), []byte(tomlContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.VM.CPU != 8 {
		t.Errorf("expected overridden CPU 8, got %d", cfg.VM.CPU)
	}
	if cfg.VM.Memory != "4GiB" {
		t.Errorf("expected default Memory 4GiB, got %s", cfg.VM.Memory)
	}
	if cfg.Dev.Ports != "3000:9999" {
		t.Errorf("expected default Ports 3000:9999, got %s", cfg.Dev.Ports)
	}
}

func TestTOMLPreferredOverYAML(t *testing.T) {
	dir := t.TempDir()

	tomlContent := `[vm]
cpu = 4
`
	yamlContent := `vm:
  cpu: 2
`
	err := os.WriteFile(filepath.Join(dir, "airlock.toml"), []byte(tomlContent), 0644)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(dir, "airlock.yaml"), []byte(yamlContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.VM.CPU != 4 {
		t.Errorf("expected TOML value 4, got %d", cfg.VM.CPU)
	}
}

func TestConfigFileDetection(t *testing.T) {
	dir := t.TempDir()

	path, format := ConfigFile(dir)
	if path != "" || format != "" {
		t.Errorf("expected no config, got path=%s format=%s", path, format)
	}

	err := os.WriteFile(filepath.Join(dir, "airlock.yml"), []byte("vm:\n  cpu: 2\n"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	path, format = ConfigFile(dir)
	if format != "yaml" {
		t.Errorf("expected yaml, got %s", format)
	}

	err = os.WriteFile(filepath.Join(dir, "airlock.toml"), []byte("[vm]\ncpu = 4\n"), 0644)
	if err != nil {
		t.Fatal(err)
	}
	path, format = ConfigFile(dir)
	if format != "toml" {
		t.Errorf("expected toml (preferred), got %s", format)
	}
}

func TestValidateInvalidProfile(t *testing.T) {
	dir := t.TempDir()
	tomlContent := `
[security]
profile = "invalid"
`
	err := os.WriteFile(filepath.Join(dir, "airlock.toml"), []byte(tomlContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Load(dir)
	if err == nil {
		t.Fatal("expected validation error for invalid profile")
	}
}

func TestValidateInvalidRuntime(t *testing.T) {
	dir := t.TempDir()
	tomlContent := `
[runtime]
type = "cobol"
`
	err := os.WriteFile(filepath.Join(dir, "airlock.toml"), []byte(tomlContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Load(dir)
	if err == nil {
		t.Fatal("expected validation error for invalid runtime")
	}
}

func TestValidateAbsolutePathMount(t *testing.T) {
	dir := t.TempDir()
	tomlContent := `
[[mounts]]
path = "/absolute/path"
`
	err := os.WriteFile(filepath.Join(dir, "airlock.toml"), []byte(tomlContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Load(dir)
	if err == nil {
		t.Fatal("expected validation error for absolute mount path")
	}
}

func TestValidateEmptyMountPath(t *testing.T) {
	dir := t.TempDir()
	tomlContent := `
[[mounts]]
path = ""
`
	err := os.WriteFile(filepath.Join(dir, "airlock.toml"), []byte(tomlContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Load(dir)
	if err == nil {
		t.Fatal("expected validation error for empty mount path")
	}
}

func TestValidatePathTraversalMount(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"dotdot prefix", "../etc/passwd", true},
		{"dotdot mid", "foo/../../../etc/shadow", true},
		{"dotdot trailing", "foo/bar/..", true},
		{"dotdot segment only", "..", true},
		{"valid relative", "./api", false},
		{"valid nested", "foo/bar/baz", false},
		{"valid dot", ".", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			dir := t.TempDir()
			tomlContent := fmt.Sprintf("[[mounts]]\npath = %q\n", tt.path)
			err := os.WriteFile(filepath.Join(dir, "airlock.toml"), []byte(tomlContent), 0644)
			if err != nil {
				t.Fatal(err)
			}

			_, err = Load(dir)
			if tt.wantErr && err == nil {
				t.Error("expected validation error for path traversal")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestWriteTOML(t *testing.T) {
	cfg := Defaults()
	data, err := WriteTOML(cfg)
	if err != nil {
		t.Fatalf("WriteTOML() error: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty TOML output")
	}
}

func TestWriteYAML(t *testing.T) {
	cfg := Defaults()
	data, err := WriteYAML(cfg)
	if err != nil {
		t.Fatalf("WriteYAML() error: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty YAML output")
	}
}

func TestRoundTripTOML(t *testing.T) {
	original := Defaults()
	writable := false
	original.Mounts = []MountConfig{
		{Path: "./api", Writable: &writable},
		{Path: "./shared", Inotify: true},
	}

	data, err := WriteTOML(original)
	if err != nil {
		t.Fatalf("WriteTOML() error: %v", err)
	}

	dir := t.TempDir()
	err = os.WriteFile(filepath.Join(dir, "airlock.toml"), data, 0644)
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if loaded.VM.CPU != original.VM.CPU {
		t.Errorf("roundtrip: CPU mismatch, got %d want %d", loaded.VM.CPU, original.VM.CPU)
	}
	if loaded.VM.Memory != original.VM.Memory {
		t.Errorf("roundtrip: Memory mismatch, got %s want %s", loaded.VM.Memory, original.VM.Memory)
	}
	if len(loaded.Mounts) != len(original.Mounts) {
		t.Errorf("roundtrip: mounts count mismatch, got %d want %d", len(loaded.Mounts), len(original.Mounts))
	}
}

func TestRoundTripYAML(t *testing.T) {
	original := Defaults()
	writable := false
	original.Mounts = []MountConfig{
		{Path: "./data", Writable: &writable, Inotify: true},
	}

	data, err := WriteYAML(original)
	if err != nil {
		t.Fatalf("WriteYAML() error: %v", err)
	}

	dir := t.TempDir()
	err = os.WriteFile(filepath.Join(dir, "airlock.yaml"), data, 0644)
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if loaded.VM.CPU != original.VM.CPU {
		t.Errorf("roundtrip: CPU mismatch, got %d want %d", loaded.VM.CPU, original.VM.CPU)
	}
	if len(loaded.Mounts) != len(original.Mounts) {
		t.Errorf("roundtrip: mounts count mismatch, got %d want %d", len(loaded.Mounts), len(original.Mounts))
	}
}
