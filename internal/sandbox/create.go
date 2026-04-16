package sandbox

import (
	"context"
	"fmt"

	"github.com/muneebs/airlock/internal/api"
	"github.com/muneebs/airlock/internal/detect"
	"github.com/muneebs/airlock/internal/profile"
)

// Create orchestrates the full sandbox creation workflow:
// validate → check resources → detect runtime → resolve profile → create VM →
// apply network policy → register mounts.
func (m *Manager) Create(ctx context.Context, spec api.SandboxSpec) (api.SandboxInfo, error) {
	if spec.Name == "" {
		return api.SandboxInfo{}, ErrInvalidSpec{Reason: "name is required"}
	}

	m.mu.Lock()
	if _, exists := m.sandboxes[spec.Name]; exists {
		m.mu.Unlock()
		return api.SandboxInfo{}, ErrAlreadyExists{Name: spec.Name}
	}
	m.mu.Unlock()

	issues := m.checkRes(spec)
	if len(issues) > 0 {
		return api.SandboxInfo{}, fmt.Errorf("insufficient resources: %v", issues)
	}

	runtimeType, err := m.resolveRuntime(spec)
	if err != nil {
		return api.SandboxInfo{}, fmt.Errorf("resolve runtime: %w", err)
	}

	prof, profName, err := m.resolveProfile(spec)
	if err != nil {
		return api.SandboxInfo{}, fmt.Errorf("resolve profile: %w", err)
	}

	info := newSandboxInfo(spec, string(runtimeType), profName)
	m.mu.Lock()
	if err := m.put(info); err != nil {
		m.mu.Unlock()
		return api.SandboxInfo{}, fmt.Errorf("save sandbox state: %w", err)
	}
	m.mu.Unlock()

	vmSpec := resolveResources(spec, prof, defaultSpec())

	if err := m.provider.Create(ctx, vmSpec); err != nil {
		m.mu.Lock()
		info.State = api.StateErrored
		_ = m.put(info)
		m.mu.Unlock()
		return api.SandboxInfo{}, fmt.Errorf("create VM: %w", err)
	}

	if err := m.provider.Start(ctx, spec.Name); err != nil {
		m.mu.Lock()
		info.State = api.StateErrored
		_ = m.put(info)
		m.mu.Unlock()
		return api.SandboxInfo{}, fmt.Errorf("start VM: %w", err)
	}

	if err := m.applyNetworkPolicy(ctx, spec.Name, prof); err != nil {
		m.mu.Lock()
		info.State = api.StateErrored
		_ = m.put(info)
		m.mu.Unlock()
		return api.SandboxInfo{}, fmt.Errorf("apply network policy: %w", err)
	}

	if spec.Source != "" {
		if err := m.mounts.Register(ctx, spec.Name, api.Mount{
			Name:     spec.Name,
			HostPath: spec.Source,
			Writable: prof.Mount.Writable,
			Inotify:  true,
		}); err != nil {
			m.mu.Lock()
			info.State = api.StateErrored
			_ = m.put(info)
			m.mu.Unlock()
			return api.SandboxInfo{}, fmt.Errorf("register mount: %w", err)
		}
	}

	if spec.Ephemeral {
		info.State = api.StateRunning
	} else {
		info.State = api.StateRunning
	}

	m.mu.Lock()
	if err := m.put(info); err != nil {
		m.mu.Unlock()
		return *info, fmt.Errorf("save sandbox state: %w", err)
	}
	m.mu.Unlock()

	return *info, nil
}

func (m *Manager) resolveRuntime(spec api.SandboxSpec) (api.RuntimeType, error) {
	if spec.Runtime != "" {
		return detect.ResolveRuntimeType(spec.Runtime)
	}

	if spec.Source != "" {
		detected, err := m.detector.Detect(spec.Source)
		if err != nil {
			return api.RuntimeUnknown, fmt.Errorf("auto-detect runtime in %s: %w", spec.Source, err)
		}
		return detected.Type, nil
	}

	return api.RuntimeUnknown, nil
}

func (m *Manager) resolveProfile(spec api.SandboxSpec) (profile.Profile, string, error) {
	profName := spec.Profile
	if profName == "" {
		profName = "cautious"
	}

	prof, err := m.profiles.Get(profName)
	if err != nil {
		return profile.Profile{}, "", fmt.Errorf("profile %q: %w", profName, err)
	}
	return prof, profName, nil
}

func (m *Manager) applyNetworkPolicy(ctx context.Context, name string, prof profile.Profile) error {
	policy := api.NetworkPolicy{
		AllowDNS:         prof.Network.AllowDNS,
		AllowOutbound:    prof.Network.AllowOutbound,
		AllowEstablished: prof.Network.AllowEstablished,
		LockAfterSetup:   prof.Network.LockAfterSetup,
	}

	if err := m.network.ApplyPolicy(ctx, name, policy); err != nil {
		return err
	}

	if prof.Network.LockAfterSetup {
		if err := m.network.Lock(ctx, name); err != nil {
			return err
		}
	}

	return nil
}

func defaultSpec() api.SandboxSpec {
	cpu := 2
	return api.SandboxSpec{
		CPU:    &cpu,
		Memory: "4GiB",
		Disk:   "20GiB",
		Ports:  "3000:9999",
	}
}
