package mount

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/muneebs/airlock/internal/api"
)

func TestNewJSONStoreCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mounts.json")

	s, err := NewJSONStore(path)
	if err != nil {
		t.Fatalf("NewJSONStore() error: %v", err)
	}
	if s.Count() != 0 {
		t.Errorf("expected empty store, got %d mounts", s.Count())
	}
}

func TestRegisterAndList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mounts.json")

	s, err := NewJSONStore(path)
	if err != nil {
		t.Fatalf("NewJSONStore() error: %v", err)
	}

	mount := api.Mount{
		Name:     "myproject",
		HostPath: "/Users/test/projects/myproject",
		VMPath:   "/home/airlock/projects/myproject",
		Writable: true,
		Inotify:  false,
	}

	err = s.Register(context.Background(), "test", mount)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	if s.Count() != 1 {
		t.Errorf("expected 1 mount, got %d", s.Count())
	}

	mounts, err := s.List(context.Background(), "test")
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if len(mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(mounts))
	}
	if mounts[0].Name != "myproject" {
		t.Errorf("expected name myproject, got %s", mounts[0].Name)
	}
}

func TestRegisterUpdatesExistingHostPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mounts.json")

	s, err := NewJSONStore(path)
	if err != nil {
		t.Fatalf("NewJSONStore() error: %v", err)
	}

	mount1 := api.Mount{
		Name:     "myproject",
		HostPath: "/Users/test/projects/myproject",
		Writable: true,
	}
	err = s.Register(context.Background(), "test", mount1)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	mount2 := api.Mount{
		Name:     "myproject",
		HostPath: "/Users/test/projects/myproject",
		Writable: false,
	}
	err = s.Register(context.Background(), "test", mount2)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	if s.Count() != 1 {
		t.Errorf("expected 1 mount (updated), got %d", s.Count())
	}

	mounts, _ := s.List(context.Background(), "test")
	if mounts[0].Writable != false {
		t.Error("expected mount to be updated to writable=false")
	}
}

func TestRegisterHandlesNameCollision(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mounts.json")

	s, err := NewJSONStore(path)
	if err != nil {
		t.Fatalf("NewJSONStore() error: %v", err)
	}

	mount1 := api.Mount{
		Name:     "project",
		HostPath: "/path/a/project",
	}
	err = s.Register(context.Background(), "test", mount1)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	mount2 := api.Mount{
		Name:     "project",
		HostPath: "/path/b/project",
	}
	err = s.Register(context.Background(), "test", mount2)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	mounts, _ := s.List(context.Background(), "test")
	if len(mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(mounts))
	}

	names := map[string]bool{}
	for _, m := range mounts {
		names[m.Name] = true
	}
	if !names["project"] || !names["project-2"] {
		t.Errorf("expected names 'project' and 'project-2', got %v", names)
	}
}

func TestUnregister(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mounts.json")

	s, err := NewJSONStore(path)
	if err != nil {
		t.Fatalf("NewJSONStore() error: %v", err)
	}

	mount := api.Mount{
		Name:     "myproject",
		HostPath: "/Users/test/projects/myproject",
	}
	s.Register(context.Background(), "test", mount)

	err = s.Unregister(context.Background(), "test", "myproject")
	if err != nil {
		t.Fatalf("Unregister() error: %v", err)
	}

	if s.Count() != 0 {
		t.Errorf("expected 0 mounts after unregister, got %d", s.Count())
	}
}

func TestPersistenceAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mounts.json")

	s1, err := NewJSONStore(path)
	if err != nil {
		t.Fatalf("NewJSONStore() error: %v", err)
	}

	mount := api.Mount{
		Name:     "persist-test",
		HostPath: "/path/to/project",
		Writable: true,
		Inotify:  true,
	}
	s1.Register(context.Background(), "test", mount)

	s2, err := NewJSONStore(path)
	if err != nil {
		t.Fatalf("NewJSONStore() error: %v", err)
	}

	if s2.Count() != 1 {
		t.Errorf("expected 1 mount from persistence, got %d", s2.Count())
	}

	mounts, _ := s2.List(context.Background(), "test")
	if mounts[0].Name != "persist-test" {
		t.Errorf("expected name persist-test, got %s", mounts[0].Name)
	}
	if !mounts[0].Inotify {
		t.Error("expected inotify=true to persist")
	}
}

func TestLoadEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mounts.json")
	os.WriteFile(path, []byte(""), 0644)

	s, err := NewJSONStore(path)
	if err != nil {
		t.Fatalf("NewJSONStore() error: %v", err)
	}
	if s.Count() != 0 {
		t.Errorf("expected empty store, got %d mounts", s.Count())
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"myproject", "myproject"},
		{"../../etc/shadow", "shadow"},
		{"/absolute/path/project", "project"},
		{"..", "mount"},
		{".", "mount"},
		{"", "mount"},
		{"foo..bar", "foobar"},
		{"a/../../../b", "b"},
	}
	for _, tt := range tests {
		got := sanitizeName(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestRegisterSanitizesName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mounts.json")

	s, err := NewJSONStore(path)
	if err != nil {
		t.Fatalf("NewJSONStore() error: %v", err)
	}

	mount := api.Mount{
		Name:     "../../etc/shadow",
		HostPath: "/tmp/test",
	}
	err = s.Register(context.Background(), "test", mount)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	mounts, _ := s.List(context.Background(), "test")
	if mounts[0].Name != "shadow" {
		t.Errorf("expected sanitized name 'shadow', got %q", mounts[0].Name)
	}
	if mounts[0].VMPath != "/home/airlock/projects/shadow" {
		t.Errorf("expected VMPath '/home/airlock/projects/shadow', got %q", mounts[0].VMPath)
	}
}
