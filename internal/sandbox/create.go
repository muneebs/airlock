package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

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

	// Remote sources are git-cloned into the VM. This must happen after the VM
	// boots but BEFORE the network policy is applied: a locking profile
	// (cautious/strict/agent) would otherwise block git from reaching the
	// remote. A freshly booted VM has open egress until applyNetworkPolicy runs.
	if isRemoteSource(spec.Source) {
		report("cloning source")
		if err := m.cloneRemoteSource(ctx, spec.Name, spec.Source); err != nil {
			if delErr := m.provider.Delete(ctx, spec.Name); delErr != nil {
				fmt.Fprintf(os.Stderr, "warning: rollback delete VM %q: %v\n", spec.Name, delErr)
			}
			m.mu.Lock()
			info.State = api.StateErrored
			_ = m.put(info)
			m.mu.Unlock()
			return api.SandboxInfo{}, fmt.Errorf("clone source: %w", err)
		}
	}

	if !opts.SkipNetworkPolicy {
		report("applying network policy")
		if err := m.applyNetworkPolicy(ctx, spec.Name, prof, spec.LockNetworkAfterSetup); err != nil {
			// The VM is booted with open egress at this point (and, for a remote
			// source, already holds the cloned code). Leaving it running without
			// the requested restrictions is worse than not creating it, so tear
			// it down rather than just marking the record errored.
			if delErr := m.provider.Delete(ctx, spec.Name); delErr != nil {
				fmt.Fprintf(os.Stderr, "warning: rollback delete VM %q: %v\n", spec.Name, delErr)
			}
			m.mu.Lock()
			info.State = api.StateErrored
			_ = m.put(info)
			m.mu.Unlock()
			return api.SandboxInfo{}, fmt.Errorf("apply network policy: %w", err)
		}
	}

	// Only local sources are host mounts. Remote sources live inside the VM
	// (cloned above), so there is nothing to register.
	if spec.Source != "" && !isRemoteSource(spec.Source) {
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

// cloneRemoteSource git-clones a remote SandboxSpec.Source into the sandbox's
// project directory as the airlock user, so the repo lands where Shell and Run
// expect it (/home/airlock/projects/<name>). The URL is normalized and
// validated by remoteCloneURL; git receives it as a distinct, shell-escaped
// argument via ExecAsUser.
func (m *Manager) cloneRemoteSource(ctx context.Context, name, source string) error {
	url, ok := remoteCloneURL(source)
	if !ok {
		return fmt.Errorf("unsupported or invalid remote source %q", source)
	}
	// Defence in depth: the VM name is already charset-validated by the provider
	// before we get here, but this helper builds a guest path from it directly,
	// so reject any name that could escape /home/airlock/projects/<name> rather
	// than rely on the caller.
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("invalid sandbox name %q", name)
	}
	dest := "/home/airlock/projects/" + name
	if _, err := m.provider.ExecAsUser(ctx, name, "airlock", []string{"git", "clone", url, dest}); err != nil {
		// Redact any userinfo (https://user:token@host) so a credential-bearing
		// clone URL never reaches logs or CLI output.
		return fmt.Errorf("git clone %s: %w", redactURLCredentials(url), err)
	}
	return nil
}

// redactURLCredentials strips a "user:pass@" / "token@" userinfo component from a
// URL so it is safe to log. Non-URL or userinfo-free strings are returned as-is.
func redactURLCredentials(rawURL string) string {
	schemeEnd := strings.Index(rawURL, "//")
	if schemeEnd == -1 {
		return rawURL
	}
	authStart := schemeEnd + 2
	at := strings.Index(rawURL[authStart:], "@")
	if at == -1 {
		return rawURL
	}
	return rawURL[:authStart] + "***@" + rawURL[authStart+at+1:]
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
	return m.applyNetworkPolicy(ctx, name, prof, nil)
}

func (m *Manager) applyNetworkPolicy(ctx context.Context, name string, prof api.Profile, lockOverride *bool) error {
	lockAfter := prof.Network.LockAfterSetup
	if lockOverride != nil {
		lockAfter = *lockOverride
	}

	policy := api.NetworkPolicy{
		AllowDNS:         prof.Network.AllowDNS,
		AllowOutbound:    prof.Network.AllowOutbound,
		AllowEstablished: prof.Network.AllowEstablished,
		LockAfterSetup:   lockAfter,
		// Carry the profile's host allowlist through to the applied policy (and
		// the subsequent Lock, which preserves it). Without this the agent
		// profile's allowlist is silently dropped and the API hosts stay blocked.
		AllowlistHosts: append([]string(nil), prof.Network.AllowlistHosts...),
	}

	if err := m.network.ApplyPolicy(ctx, name, policy); err != nil {
		return err
	}

	if lockAfter {
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
