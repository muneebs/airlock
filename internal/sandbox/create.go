package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/muneebs/airlock/internal/api"
	"github.com/muneebs/airlock/internal/detect"
)

// Create orchestrates the full sandbox creation workflow:
// validate → check resources → detect runtime → resolve profile → create VM →
// apply network policy → register mounts.
func (m *Manager) Create(ctx context.Context, spec api.SandboxSpec) (api.SandboxInfo, error) {
	return m.CreateWithProgress(ctx, spec, nil)
}

// CreateWithProgress is Create instrumented with a stage-name callback so
// UI callers can display which sub-step is executing. The callback is
// invoked synchronously on the calling goroutine; keep it cheap. nil is
// allowed and disables reporting.
func (m *Manager) CreateWithProgress(ctx context.Context, spec api.SandboxSpec, progress api.ProgressFn) (api.SandboxInfo, error) {
	return m.CreateWithOptions(ctx, spec, api.CreateOptions{Progress: progress})
}

// CreateWithOptions is the full-options variant of Create.
func (m *Manager) CreateWithOptions(ctx context.Context, spec api.SandboxSpec, opts api.CreateOptions) (api.SandboxInfo, error) {
	report := func(stage string) {
		if opts.Progress != nil {
			opts.Progress(stage)
		}
	}

	report("validating spec")
	if spec.Name == "" {
		return api.SandboxInfo{}, ErrInvalidSpec{Reason: "name is required"}
	}

	report("checking host resources")
	issues := m.checkRes(spec)
	if len(issues) > 0 {
		return api.SandboxInfo{}, fmt.Errorf("insufficient resources: %v", issues)
	}

	report("resolving runtime")
	runtimeType, err := m.resolveRuntime(spec)
	if err != nil {
		return api.SandboxInfo{}, fmt.Errorf("resolve runtime: %w", err)
	}

	report("resolving security profile")
	prof, profName, err := m.resolveProfile(spec)
	if err != nil {
		return api.SandboxInfo{}, fmt.Errorf("resolve profile: %w", err)
	}

	info := newSandboxInfo(spec, string(runtimeType), profName)

	report("registering sandbox state")
	m.mu.Lock()
	if existing, exists := m.sandboxes[spec.Name]; exists {
		// States that signal a prior attempt did not finish cleanly:
		// - errored: we explicitly marked failure
		// - creating: the process died (ctrl-c, crash) before final state was saved
		recoverable := existing.State == api.StateErrored || existing.State == api.StateCreating
		if !recoverable {
			m.mu.Unlock()
			return api.SandboxInfo{}, ErrAlreadyExists{Name: spec.Name}
		}
		_ = m.remove(spec.Name)
		m.mu.Unlock()
		report("deleting prior VM")
		if delErr := m.provider.Delete(ctx, spec.Name); delErr != nil {
			fmt.Fprintf(os.Stderr, "warning: delete prior %s VM %q: %v\n", existing.State, spec.Name, delErr)
		}
		m.mu.Lock()
	}
	if err := m.put(info); err != nil {
		m.mu.Unlock()
		return api.SandboxInfo{}, fmt.Errorf("save sandbox state: %w", err)
	}
	m.mu.Unlock()

	vmSpec := resolveResources(spec, prof, defaultSpec())

	report("creating lima vm")
	if err := m.provider.Create(ctx, vmSpec); err != nil {
		m.mu.Lock()
		info.State = api.StateErrored
		_ = m.put(info)
		m.mu.Unlock()
		return api.SandboxInfo{}, fmt.Errorf("create VM: %w", err)
	}

	report("booting vm (waiting for ssh)")
	if err := m.provider.Start(ctx, spec.Name); err != nil {
		if delErr := m.provider.Delete(ctx, spec.Name); delErr != nil {
			fmt.Fprintf(os.Stderr, "warning: rollback delete VM %q: %v\n", spec.Name, delErr)
		}
		m.mu.Lock()
		info.State = api.StateErrored
		_ = m.put(info)
		m.mu.Unlock()
		return api.SandboxInfo{}, fmt.Errorf("start VM: %w", err)
	}

	if !opts.SkipNetworkPolicy {
		report("applying network policy")
		if err := m.applyNetworkPolicy(ctx, spec.Name, prof); err != nil {
			m.mu.Lock()
			info.State = api.StateErrored
			_ = m.put(info)
			m.mu.Unlock()
			return api.SandboxInfo{}, fmt.Errorf("apply network policy: %w", err)
		}
	}

	if spec.Source != "" {
		report("registering mount")
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

	report("saving final state")
	info.State = api.StateRunning

	m.mu.Lock()
	if err := m.put(info); err != nil {
		m.mu.Unlock()
		return api.SandboxInfo{}, fmt.Errorf("save sandbox state: %w", err)
	}
	m.mu.Unlock()

	report("ready")
	return *info, nil
}

func (m *Manager) resolveRuntime(spec api.SandboxSpec) (api.RuntimeType, error) {
	if spec.Runtime != "" {
		return detect.ResolveRuntimeType(spec.Runtime)
	}

	if spec.Source != "" {
		detected, err := m.detector.Detect(spec.Source)
		if err != nil {
			var notDetected detect.ErrNotDetected
			if errors.As(err, &notDetected) {
				return api.RuntimeUnknown, nil
			}
			return api.RuntimeUnknown, fmt.Errorf("auto-detect runtime in %s: %w", spec.Source, err)
		}
		return detected.Type, nil
	}

	return api.RuntimeUnknown, nil
}

func (m *Manager) resolveProfile(spec api.SandboxSpec) (api.Profile, string, error) {
	profName := spec.Profile
	if profName == "" {
		profName = "cautious"
	}

	prof, err := m.profiles.Get(profName)
	if err != nil {
		return api.Profile{}, "", fmt.Errorf("profile %q: %w", profName, err)
	}
	return prof, profName, nil
}

// ApplyNetworkProfile applies the network policy of the sandbox's stored
// profile. Setup uses this to defer iptables setup until after provisioning
// has installed the iptables package.
func (m *Manager) ApplyNetworkProfile(ctx context.Context, name string) error {
	m.mu.Lock()
	info, err := m.get(name)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	prof, perr := m.profiles.Get(info.Profile)
	if perr != nil {
		return fmt.Errorf("resolve profile %q: %w", info.Profile, perr)
	}
	return m.applyNetworkPolicy(ctx, name, prof)
}

func (m *Manager) applyNetworkPolicy(ctx context.Context, name string, prof api.Profile) error {
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
