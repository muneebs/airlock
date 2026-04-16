// Package sandbox orchestrates sandbox lifecycle by coordinating runtime detection,
// security profile resolution, VM provisioning, network policy application, and mount
// management. It depends on interfaces defined in the api package and never on
// concrete implementations.
package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/muneebs/airlock/internal/api"
	"github.com/muneebs/airlock/internal/detect"
	"github.com/muneebs/airlock/internal/sysutil"
)

// Resetter extends the VM Provider with snapshot restore capabilities.
// Concrete implementations (like LimaProvider) satisfy this interface
// to support sandbox reset.
type Resetter interface {
	RestoreClean(ctx context.Context, name string) error
	HasCleanSnapshot(ctx context.Context, name string) (bool, error)
}

// ResourceChecker validates that the host has sufficient resources for a sandbox.
// Returns a list of insufficiencies (empty if everything is fine).
type ResourceChecker func(spec api.SandboxSpec) []sysutil.Insufficiency

// Manager orchestrates sandbox creation, execution, and teardown by delegating
// to injectable dependencies. It implements api.SandboxManager.
type Manager struct {
	provider  api.Provider
	resetter  Resetter
	detector  *detect.CompositeDetector
	profiles  api.ProfileRegistry
	mounts    api.MountManager
	network   api.NetworkController
	storePath string
	checkRes  ResourceChecker

	mu        sync.Mutex
	sandboxes map[string]*api.SandboxInfo
}

// NewManager creates a sandbox Manager with all required dependencies.
func NewManager(
	provider api.Provider,
	resetter Resetter,
	detector *detect.CompositeDetector,
	profiles api.ProfileRegistry,
	mounts api.MountManager,
	network api.NetworkController,
	storePath string,
) (*Manager, error) {
	m := &Manager{
		provider:  provider,
		resetter:  resetter,
		detector:  detector,
		profiles:  profiles,
		mounts:    mounts,
		network:   network,
		storePath: storePath,
		checkRes:  CheckResourcesForSpec,
		sandboxes: make(map[string]*api.SandboxInfo),
	}

	if err := m.load(); err != nil {
		return nil, fmt.Errorf("load sandbox store: %w", err)
	}

	return m, nil
}

func (m *Manager) load() error {
	data, err := os.ReadFile(m.storePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read store: %w", err)
	}
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, &m.sandboxes)
}

func (m *Manager) save() error {
	dir := filepath.Dir(m.storePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create store dir: %w", err)
	}
	data, err := json.MarshalIndent(m.sandboxes, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sandboxes: %w", err)
	}
	return os.WriteFile(m.storePath, data, 0644)
}

func (m *Manager) get(name string) (*api.SandboxInfo, error) {
	info, ok := m.sandboxes[name]
	if !ok {
		return nil, ErrNotFound{Name: name}
	}
	return info, nil
}

func (m *Manager) put(info *api.SandboxInfo) error {
	m.sandboxes[info.Name] = info
	return m.save()
}

func (m *Manager) remove(name string) error {
	delete(m.sandboxes, name)
	return m.save()
}

func derefInt(p *int, def int) int {
	if p != nil {
		return *p
	}
	return def
}

// resolveResources merges spec overrides with profile defaults and config defaults.
func resolveResources(spec api.SandboxSpec, prof api.Profile, cfgDefaults api.SandboxSpec) api.VMSpec {
	cpu := derefInt(cfgDefaults.CPU, 2)
	if spec.CPU != nil {
		cpu = *spec.CPU
	}

	memory := cfgDefaults.Memory
	if spec.Memory != "" {
		memory = spec.Memory
	}

	disk := cfgDefaults.Disk
	if spec.Disk != "" {
		disk = spec.Disk
	}

	vmSpec := api.VMSpec{
		Name:   spec.Name,
		OS:     "Linux",
		Arch:   "default",
		CPU:    cpu,
		Memory: memory,
		Disk:   disk,
		Ports:  spec.Ports,
	}

	if spec.Source != "" {
		vmSpec.Mounts = append(vmSpec.Mounts, api.VMMount{
			HostPath:  spec.Source,
			GuestPath: "/home/airlock/projects/" + spec.Name,
			Writable:  prof.Mount.Writable,
			Inotify:   true,
		})
	}

	return vmSpec
}

// ErrNotFound is returned when a sandbox name does not exist.
type ErrNotFound struct {
	Name string
}

func (e ErrNotFound) Error() string {
	return "sandbox not found: " + e.Name
}

// ErrAlreadyExists is returned when creating a sandbox that already exists.
type ErrAlreadyExists struct {
	Name string
}

func (e ErrAlreadyExists) Error() string {
	return "sandbox already exists: " + e.Name
}

// ErrInvalidSpec is returned when a sandbox spec fails validation.
type ErrInvalidSpec struct {
	Reason string
}

func (e ErrInvalidSpec) Error() string {
	return "invalid spec: " + e.Reason
}

// SandboxStateFromVM maps a VM running state to a SandboxState.
func SandboxStateFromVM(running bool, errored bool) api.SandboxState {
	if errored {
		return api.StateErrored
	}
	if running {
		return api.StateRunning
	}
	return api.StateStopped
}

// newSandboxInfo creates a SandboxInfo from a spec and resolved profile name.
func newSandboxInfo(spec api.SandboxSpec, runtime string, profName string) *api.SandboxInfo {
	cpu := 2
	if spec.CPU != nil {
		cpu = *spec.CPU
	}
	memory := spec.Memory
	if memory == "" {
		memory = "4GiB"
	}
	disk := spec.Disk
	if disk == "" {
		disk = "20GiB"
	}

	return &api.SandboxInfo{
		Name:      spec.Name,
		State:     api.StateCreating,
		Profile:   profName,
		Runtime:   runtime,
		Source:    spec.Source,
		CreatedAt: time.Now(),
		Ephemeral: spec.Ephemeral,
		CPU:       cpu,
		Memory:    memory,
		Disk:      disk,
	}
}

// CheckResourcesForSpec validates that the host has enough resources for a sandbox.
func CheckResourcesForSpec(spec api.SandboxSpec) []sysutil.Insufficiency {
	cpu := 2
	if spec.CPU != nil {
		cpu = *spec.CPU
	}
	memory := spec.Memory
	if memory == "" {
		memory = "4GiB"
	}
	disk := spec.Disk
	if disk == "" {
		disk = "20GiB"
	}

	available := sysutil.DetectResources()
	issues, _ := sysutil.CheckResources(sysutil.Requirements{
		CPU:    cpu,
		Memory: memory,
		Disk:   disk,
	}, available)
	return issues
}

// SetCheckResources overrides the resource checker. Tests use this to
// bypass resource checks that would fail in constrained environments.
func (m *Manager) SetCheckResources(fn ResourceChecker) {
	m.checkRes = fn
}

// Verify Manager implements api.SandboxManager at compile time.
var _ api.SandboxManager = (*Manager)(nil)
