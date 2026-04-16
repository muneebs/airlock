package detect

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/muneebs/airlock/internal/api"
)

func TestNodeDetection(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{}`), 0644)

	d := NewCompositeDetector()
	result, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.Type != api.RuntimeNode {
		t.Errorf("expected node, got %s", result.Type)
	}
	if result.InstallCmd == "" {
		t.Error("expected non-empty install command")
	}
}

func TestNodeDetectionWithPnpm(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{}`), 0644)
	os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(""), 0644)

	d := NewCompositeDetector()
	result, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.Type != api.RuntimeNode {
		t.Errorf("expected node, got %s", result.Type)
	}
	if result.InstallCmd != "pnpm install --frozen-lockfile" {
		t.Errorf("expected pnpm install, got %s", result.InstallCmd)
	}
}

func TestGoDetection(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\ngo 1.21\n"), 0644)

	d := NewCompositeDetector()
	result, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.Type != api.RuntimeGo {
		t.Errorf("expected go, got %s", result.Type)
	}
}

func TestRustDetection(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(`[package]
name = "test"
version = "0.1.0"
`), 0644)

	d := NewCompositeDetector()
	result, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.Type != api.RuntimeRust {
		t.Errorf("expected rust, got %s", result.Type)
	}
}

func TestPythonDetection(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask\n"), 0644)

	d := NewCompositeDetector()
	result, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.Type != api.RuntimePython {
		t.Errorf("expected python, got %s", result.Type)
	}
}

func TestDockerComposeBeatsDockerfile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM alpine\n"), 0644)
	os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("version: '3'\n"), 0644)

	d := NewCompositeDetector()
	result, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.Type != api.RuntimeCompose {
		t.Errorf("expected compose to take priority over Dockerfile, got %s", result.Type)
	}
	if !result.NeedsDocker {
		t.Error("expected NeedsDocker=true for compose")
	}
}

func TestDockerfileDetection(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM alpine\n"), 0644)

	d := NewCompositeDetector()
	result, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.Type != api.RuntimeDocker {
		t.Errorf("expected docker, got %s", result.Type)
	}
	if !result.NeedsDocker {
		t.Error("expected NeedsDocker=true for Dockerfile")
	}
}

func TestDockerComposeModernFilenames(t *testing.T) {
	tests := []struct {
		name     string
		filename string
	}{
		{"docker-compose.yml", "docker-compose.yml"},
		{"docker-compose.yaml", "docker-compose.yaml"},
		{"compose.yml", "compose.yml"},
		{"compose.yaml", "compose.yaml"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			os.WriteFile(filepath.Join(dir, tt.filename), []byte("services:\n  web:\n    image: nginx\n"), 0644)

			d := NewCompositeDetector()
			result, err := d.Detect(dir)
			if err != nil {
				t.Fatalf("Detect() error: %v", err)
			}
			if result.Type != api.RuntimeCompose {
				t.Errorf("expected compose, got %s", result.Type)
			}
		})
	}
}

func TestDockerfileDetectorSkipsModernCompose(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM alpine\n"), 0644)
	os.WriteFile(filepath.Join(dir, "compose.yml"), []byte("services:\n  web:\n    image: nginx\n"), 0644)

	d := NewCompositeDetector()
	result, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.Type != api.RuntimeCompose {
		t.Errorf("expected compose to take priority over Dockerfile when compose.yml exists, got %s", result.Type)
	}
}

func TestMakefileDetection(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "Makefile"), []byte("all:\n\techo hello\n"), 0644)

	d := NewCompositeDetector()
	result, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.Type != api.RuntimeMake {
		t.Errorf("expected make, got %s", result.Type)
	}
	if result.Confidence >= 0.9 {
		t.Error("makefile detection should have low confidence since it's a fallback")
	}
}

func TestDotnetDetection(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.csproj"), []byte(`<Project Sdk="Microsoft.NET.Sdk"></Project>`), 0644)

	d := NewCompositeDetector()
	result, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.Type != api.RuntimeDotNet {
		t.Errorf("expected dotnet, got %s", result.Type)
	}
}

func TestNoDetection(t *testing.T) {
	dir := t.TempDir()

	d := NewCompositeDetector()
	_, err := d.Detect(dir)
	if err == nil {
		t.Error("expected error for empty directory")
	}
}

func TestComposePriorityOverNode(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{}`), 0644)
	os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("version: '3'\n"), 0644)

	d := NewCompositeDetector()
	result, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.Type != api.RuntimeCompose {
		t.Errorf("expected compose to take priority over node, got %s", result.Type)
	}
}

func TestSupportedTypes(t *testing.T) {
	d := NewCompositeDetector()
	types := d.SupportedTypes()
	if len(types) < 8 {
		t.Errorf("expected at least 8 supported types, got %d", len(types))
	}
}

func TestResolveRuntimeType(t *testing.T) {
	tests := []struct {
		input    string
		expected api.RuntimeType
		wantErr  bool
	}{
		{"node", api.RuntimeNode, false},
		{"go", api.RuntimeGo, false},
		{"rust", api.RuntimeRust, false},
		{"python", api.RuntimePython, false},
		{"docker", api.RuntimeDocker, false},
		{"compose", api.RuntimeCompose, false},
		{"make", api.RuntimeMake, false},
		{"dotnet", api.RuntimeDotNet, false},
		{"Node", api.RuntimeNode, false},
		{"cobol", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ResolveRuntimeType(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if got != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, got)
			}
		})
	}
}

func TestCustomDetector(t *testing.T) {
	d := NewCompositeDetector()

	custom := &staticDetector{
		runtimeType: api.RuntimeType("elixir"),
		priority:    15,
		result: api.DetectedRuntime{
			Type:       api.RuntimeType("elixir"),
			InstallCmd: "mix deps.get",
			RunCmd:     "mix phx.server",
			Confidence: 0.9,
		},
	}

	d.Register(custom)

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "mix.exs"), []byte("defmodule"), 0644)

	result, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.Type != api.RuntimeType("elixir") {
		t.Errorf("expected custom detector to work, got %s", result.Type)
	}
}

type staticDetector struct {
	runtimeType api.RuntimeType
	priority    int
	result      api.DetectedRuntime
	err         error
}

func (s *staticDetector) Type() api.RuntimeType { return s.runtimeType }
func (s *staticDetector) Priority() int         { return s.priority }
func (s *staticDetector) Detect(dir string) (api.DetectedRuntime, error) {
	return s.result, s.err
}

func TestDetectorFailFastOnError(t *testing.T) {
	d := NewCompositeDetector()

	realErr := fmt.Errorf("permission denied")

	highPriority := &staticDetector{
		runtimeType: api.RuntimeType("broken"),
		priority:    1,
		err:         realErr,
	}
	lowPriority := &staticDetector{
		runtimeType: api.RuntimeType("node"),
		priority:    100,
		result:      api.DetectedRuntime{Type: api.RuntimeNode, InstallCmd: "npm ci"},
	}

	d.Register(highPriority)
	d.Register(lowPriority)

	dir := t.TempDir()
	_, err := d.Detect(dir)
	if err == nil {
		t.Fatal("expected error from broken detector")
	}
	if !errors.Is(err, realErr) {
		t.Errorf("expected real error to propagate, got: %v", err)
	}
}

func TestDetectorWrappedErrNotDetected(t *testing.T) {
	d := NewCompositeDetector()

	wrapped := &staticDetector{
		runtimeType: api.RuntimeType("wrapped"),
		priority:    1,
		err:         fmt.Errorf("wrapper: %w", ErrNotDetected{Dir: "/test"}),
	}

	success := &staticDetector{
		runtimeType: api.RuntimeType("node"),
		priority:    100,
		result:      api.DetectedRuntime{Type: api.RuntimeNode, InstallCmd: "npm ci"},
	}

	d.Register(wrapped)
	d.Register(success)

	dir := t.TempDir()
	result, err := d.Detect(dir)
	if err != nil {
		t.Fatalf("expected wrapped ErrNotDetected to cause continuation, got: %v", err)
	}
	if result.Type != api.RuntimeNode {
		t.Errorf("expected node result, got %s", result.Type)
	}
}
