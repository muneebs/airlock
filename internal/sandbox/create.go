package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/muneebs/airlock/internal/api"
	"github.com/muneebs/airlock/internal/detect"
)

// rollbackTimeout bounds the cleanup Delete run when create fails partway. It is
// generous because tearing down a Lima VM can be slow, but finite so a wedged
// provider can't block create's return indefinitely.
const rollbackTimeout = 2 * time.Minute

// rollbackVM tears a half-created VM down, marks its store record errored, and
// returns opErr. The Delete runs on a context detached from ctx's cancellation
// (values retained) and bounded by rollbackTimeout: provision/clone/network
// failures are frequently caused by ctx itself being canceled or timed out, and
// reusing that same ctx for cleanup would abort the Delete and leak a running
// VM. If the cleanup Delete fails, its error is joined onto opErr so the leaked
// VM surfaces to the caller instead of being only logged.
func (m *Manager) rollbackVM(ctx context.Context, info *api.SandboxInfo, opErr error) (api.SandboxInfo, error) {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	if delErr := m.provider.Delete(cleanupCtx, info.Name); delErr != nil {
		opErr = errors.Join(opErr, fmt.Errorf("rollback delete VM %q: %w", info.Name, delErr))
	}
	m.mu.Lock()
	info.State = api.StateErrored
	_ = m.put(info)
	m.mu.Unlock()
	return api.SandboxInfo{}, opErr
}

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

	// Reserve the name for the duration of this create. A concurrent create for
	// the same name is rejected here rather than being allowed to race — without
	// this, the second create sees the first's in-progress "creating" record,
	// treats it as a crashed attempt, and tears it down, so both can proceed.
	m.mu.Lock()
	if m.creating[spec.Name] {
		m.mu.Unlock()
		return api.SandboxInfo{}, ErrAlreadyExists{Name: spec.Name}
	}
	m.creating[spec.Name] = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.creating, spec.Name)
		m.mu.Unlock()
	}()

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

	if err := m.createAndStartVM(ctx, spec.Name, vmSpec, report); err != nil {
		m.mu.Lock()
		info.State = api.StateErrored
		_ = m.put(info)
		m.mu.Unlock()
		return api.SandboxInfo{}, err
	}

	// Provision the freshly booted VM with the shared baseline+runtime steps
	// (same machinery setup uses). This must run BEFORE cloneRemoteSource — the
	// clone runs as the airlock user, which the baseline steps create — and
	// BEFORE applyNetworkPolicy, because a Node install needs open egress and a
	// locking profile would otherwise cut it off. The baseline "Preparing
	// airlock home" step chowns /home/airlock/projects so the already-mounted
	// worktree is traversable by the airlock run-user.
	if opts.Provision {
		if m.provisioner == nil {
			return api.SandboxInfo{}, fmt.Errorf("provision sandbox %q: no provisioner configured", spec.Name)
		}
		report("provisioning sandbox")
		if err := m.provisioner.ProvisionVM(ctx, spec.Name, provisionOptionsForRuntime(runtimeType)); err != nil {
			// The VM booted but is unusable without its baseline (no airlock
			// user, no runtime). Tear it down and mark the record errored, as
			// the neighboring clone/network steps do on failure.
			return m.rollbackVM(ctx, info, fmt.Errorf("provision sandbox: %w", err))
		}
	}

	// Remote sources are git-cloned into the VM. This must happen after the VM
	// boots but BEFORE the network policy is applied: a locking profile
	// (cautious/strict/agent) would otherwise block git from reaching the
	// remote. A freshly booted VM has open egress until applyNetworkPolicy runs.
	if isRemoteSource(spec.Source) {
		report("cloning source")
		if err := m.cloneRemoteSource(ctx, spec.Name, spec.Source); err != nil {
			return m.rollbackVM(ctx, info, fmt.Errorf("clone source: %w", err))
		}
	}

	if !opts.SkipNetworkPolicy {
		report("applying network policy")
		if err := m.applyNetworkPolicy(ctx, spec.Name, prof, spec.LockNetworkAfterSetup); err != nil {
			// The VM is booted with open egress at this point (and, for a remote
			// source, already holds the cloned code). Leaving it running without
			// the requested restrictions is worse than not creating it, so tear
			// it down rather than just marking the record errored.
			return m.rollbackVM(ctx, info, fmt.Errorf("apply network policy: %w", err))
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
	// info is stored by pointer in m.sandboxes and read by concurrent
	// List/Status/Create under m.mu, so its fields must only be mutated while
	// holding the lock — mutating State outside it races with those readers.
	m.mu.Lock()
	info.State = api.StateRunning
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

// mountTypeFallbacks is the ordered list of host-mount mechanisms tried when
// bringing up a VM. virtiofs is fastest but fails to mount on some macOS/Lima
// combinations; reverse-sshfs is the widely-compatible fallback. When a boot
// fails in a way that looks mount-related, the VM is recreated with the next
// mechanism.
func mountTypeFallbacks() []string { return []string{"virtiofs", "reverse-sshfs"} }

// isMountError reports whether a VM start failure looks like a host-mount
// problem, and therefore worth retrying with a different mount mechanism.
func isMountError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, s := range []string{"virtiofs", "reverse-sshfs", "sshfs", "9p", "mount"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// createAndStartVM creates and boots the VM, retrying with a fallback host-mount
// mechanism when a start failure looks mount-related. It leaves no VM behind on
// a failed attempt. A VM with no host mounts has nothing to fall back on, so a
// single attempt is made in that case.
func (m *Manager) createAndStartVM(ctx context.Context, name string, vmSpec api.VMSpec, report func(string)) error {
	types := mountTypeFallbacks()
	if len(vmSpec.Mounts) == 0 {
		types = types[:1]
	}

	var lastErr error
	for i, mt := range types {
		vmSpec.MountType = mt

		report("creating lima vm")
		if err := m.provider.Create(ctx, vmSpec); err != nil {
			return fmt.Errorf("create VM: %w", err)
		}

		report("booting vm (waiting for ssh)")
		if err := m.provider.Start(ctx, name); err != nil {
			lastErr = err
			if delErr := m.provider.Delete(ctx, name); delErr != nil {
				fmt.Fprintf(os.Stderr, "warning: rollback delete VM %q: %v\n", name, delErr)
			}
			if i < len(types)-1 && isMountError(err) {
				report(fmt.Sprintf("mount failed; retrying with %s", types[i+1]))
				continue
			}
			return fmt.Errorf("start VM: %w", lastErr)
		}
		return nil
	}
	return fmt.Errorf("start VM: %w", lastErr)
}

// provisionOptionsForRuntime maps a resolved runtime to the provisioning
// options for a per-ticket sandbox. Every runtime gets the baseline (system
// packages, airlock user, passwordless sudo, /home/airlock) via the empty
// options; node additionally requests Node.js/npm/pnpm. NodeVersion is left
// zero so ProvisionSteps applies its default (currently 22). Bun/Docker/AI
// tools are intentionally out of scope for per-ticket sandboxes.
func provisionOptionsForRuntime(rt api.RuntimeType) api.ProvisionOptions {
	opts := api.ProvisionOptions{}
	if rt == api.RuntimeNode {
		opts.InstallNode = true
	}
	return opts
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
