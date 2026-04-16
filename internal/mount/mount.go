// Package mount manages the registry of host directories mounted into sandboxes.
// It persists mount state as JSON and supports add, remove, and list operations.
package mount

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/muneebs/airlock/internal/api"
)

// JSONStore persists mount registrations to a JSON file.
type JSONStore struct {
	mu     sync.Mutex
	path   string
	mounts []api.Mount
}

// NewJSONStore creates or loads a mount store from the given file path.
func NewJSONStore(path string) (*JSONStore, error) {
	s := &JSONStore{path: path}
	if err := s.load(); err != nil {
		return nil, fmt.Errorf("load mount store: %w", err)
	}
	return s, nil
}

func (s *JSONStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.mounts = []api.Mount{}
			return nil
		}
		return err
	}
	if len(data) == 0 {
		s.mounts = []api.Mount{}
		return nil
	}
	return json.Unmarshal(data, &s.mounts)
}

func (s *JSONStore) save() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create mount store dir: %w", err)
	}
	data, err := json.MarshalIndent(s.mounts, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal mounts: %w", err)
	}
	return os.WriteFile(s.path, data, 0644)
}

// Register adds a mount to the store. If a mount with the same host path
// already exists, it is updated. If a mount with the same name but different
// host path exists, a numeric suffix is appended.
func (s *JSONStore) Register(_ context.Context, sandboxName string, m api.Mount) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	m.Name = s.resolveName(sanitizeName(m.Name), m.HostPath)
	m.VMPath = fmt.Sprintf("/home/airlock/projects/%s", m.Name)

	for i, existing := range s.mounts {
		if existing.HostPath == m.HostPath {
			s.mounts[i] = m
			return s.save()
		}
	}

	s.mounts = append(s.mounts, m)
	return s.save()
}

// Unregister removes a mount by name.
func (s *JSONStore) Unregister(_ context.Context, sandboxName string, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filtered := s.mounts[:0]
	for _, m := range s.mounts {
		if m.Name != name {
			filtered = append(filtered, m)
		}
	}
	s.mounts = filtered
	return s.save()
}

// List returns all registered mounts.
func (s *JSONStore) List(_ context.Context, sandboxName string) ([]api.Mount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := make([]api.Mount, len(s.mounts))
	copy(result, s.mounts)
	return result, nil
}

// Count returns the number of registered mounts.
func (s *JSONStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.mounts)
}

// Apply is a no-op for the JSON store. Mount application happens at the VM
// provider level when the VM is created or started.
func (s *JSONStore) Apply(_ context.Context, sandboxName string) error {
	return nil
}

func (s *JSONStore) resolveName(base, hostPath string) string {
	for _, m := range s.mounts {
		if m.HostPath == hostPath {
			return m.Name
		}
	}

	candidate := base
	counter := 1
	for {
		conflict := false
		for _, m := range s.mounts {
			if m.Name == candidate && m.HostPath != hostPath {
				conflict = true
				break
			}
		}
		if !conflict {
			return candidate
		}
		counter++
		candidate = fmt.Sprintf("%s-%d", base, counter)
	}
}

func sanitizeName(name string) string {
	name = filepath.Base(name)
	name = strings.ReplaceAll(name, "..", "")
	if name == "" || name == "." {
		name = "mount"
	}
	return name
}
