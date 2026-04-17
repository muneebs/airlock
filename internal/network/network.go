// Package network provides iptables-based network isolation for Lima VMs.
// It shells out to limactl to run iptables commands inside the sandbox VM,
// controlling whether the sandbox can make outbound connections.
package network

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/muneebs/airlock/internal/api"
)

// limactlCallTimeout bounds how long any single limactl shell invocation is
// allowed to run before we give up and surface an error. Setting iptables
// rules or running small shell commands in a healthy VM completes in under
// a second; 60s is a generous ceiling that catches hangs (ssh ControlMaster
// stuck, xtables lock held indefinitely, VM SSH daemon unresponsive) without
// interfering with legitimate slow operations.
const limactlCallTimeout = 60 * time.Second

// CommandRunner executes a command inside a Lima VM and returns an error.
// Production implementations shell out to limactl; tests provide fakes.
type CommandRunner func(ctx context.Context, vmName, cmd string) error

// OutputRunner executes a command inside a Lima VM and returns its output.
// Production implementations shell out to limactl; tests provide fakes.
type OutputRunner func(ctx context.Context, vmName, cmd string) (string, error)

// LimaController manages network isolation by executing iptables commands
// inside a Lima VM via limactl. It implements api.NetworkController.
// The sandboxName parameter on each method determines which VM to target,
// so a single controller can manage networking for multiple sandboxes.
type LimaController struct {
	runCmd    CommandRunner
	runOutput OutputRunner
	mu        sync.Mutex
	policies  map[string]api.NetworkPolicy
}

// NewLimaController creates a network controller using the default
// (production) limactl runners.
func NewLimaController() *LimaController {
	return &LimaController{
		runCmd:    limactlRunExec,
		runOutput: limactlOutputExec,
		policies:  make(map[string]api.NetworkPolicy),
	}
}

// NewLimaControllerWithRunners creates a network controller with injectable
// command runners, for testing.
func NewLimaControllerWithRunners(runCmd CommandRunner, runOutput OutputRunner) *LimaController {
	return &LimaController{
		runCmd:    runCmd,
		runOutput: runOutput,
		policies:  make(map[string]api.NetworkPolicy),
	}
}

// Lock blocks all outbound network traffic except DNS, loopback, and
// reply packets on already-established connections. ESTABLISHED must
// remain allowed or Lock kills the lima ssh session that applied the
// rule: the VM's sshd replies travel out via the OUTPUT chain, so
// dropping ESTABLISHED drops the ssh return path and every subsequent
// limactl shell call hangs until the client times out.
func (lc *LimaController) Lock(ctx context.Context, sandboxName string) error {
	policy := api.NetworkPolicy{
		AllowDNS:         true,
		AllowOutbound:    false,
		AllowEstablished: true,
	}
	return lc.ApplyPolicy(ctx, sandboxName, policy)
}

// Unlock re-enables all outbound network traffic.
func (lc *LimaController) Unlock(ctx context.Context, sandboxName string) error {
	policy := api.NetworkPolicy{
		AllowDNS:         true,
		AllowOutbound:    true,
		AllowEstablished: true,
	}
	return lc.ApplyPolicy(ctx, sandboxName, policy)
}

// ApplyPolicy applies a specific network policy using iptables rules.
// It builds the complete ruleset and applies it atomically via
// iptables-restore, so a failure never leaves the VM in a partially
// configured (exposed) state.
// LockAfterSetup in the policy is not consumed here — the sandbox orchestrator
// reads it to decide whether to call Lock() after setup completes.
//
// SECURITY: The ruleset is passed to iptables-restore via a shell heredoc
// with a quoted delimiter (<<'AIRLOCK_EOF'). The single-quoted delimiter
// prevents bash from performing any interpolation (variable substitution,
// command substitution, or escape processing) on the ruleset content. This
// eliminates the command-injection risk that would exist if the ruleset were
// embedded directly in a printf or echo command. Even if NetworkPolicy gains
// string fields in the future, the heredoc content is treated as literal text.
func (lc *LimaController) ApplyPolicy(ctx context.Context, sandboxName string, policy api.NetworkPolicy) error {
	ruleset := BuildOutputRules(policy)
	cmd := fmt.Sprintf("sudo iptables-restore <<'AIRLOCK_EOF'\n%sAIRLOCK_EOF", ruleset)

	if err := lc.runCmd(ctx, sandboxName, cmd); err != nil {
		return fmt.Errorf("apply iptables policy: %w", err)
	}

	lc.mu.Lock()
	lc.policies[sandboxName] = policy
	lc.mu.Unlock()

	return nil
}

// BuildOutputRules constructs an iptables-restore format ruleset for the
// OUTPUT chain based on the given policy. The ruleset replaces the OUTPUT
// chain atomically — either all rules apply or none do.
func BuildOutputRules(policy api.NetworkPolicy) string {
	var rules strings.Builder

	rules.WriteString("*filter\n")
	rules.WriteString(":OUTPUT DROP [0:0]\n")

	// Loopback — always allowed
	rules.WriteString("-A OUTPUT -o lo -j ACCEPT\n")

	// DNS (UDP port 53)
	if policy.AllowDNS {
		rules.WriteString("-A OUTPUT -p udp --dport 53 -j ACCEPT\n")
	}

	// Established connections
	if policy.AllowEstablished {
		rules.WriteString("-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n")
	}

	// Full outbound — override the default DROP policy
	if policy.AllowOutbound {
		rules.WriteString("-A OUTPUT -j ACCEPT\n")
	}

	rules.WriteString("COMMIT\n")
	return rules.String()
}

// IsLocked checks whether the network is currently locked.
// It first checks the tracked policy state; if no policy has been applied,
// it falls back to inspecting iptables rules in the VM.
func (lc *LimaController) IsLocked(ctx context.Context, sandboxName string) (bool, error) {
	lc.mu.Lock()
	policy, applied := lc.policies[sandboxName]
	lc.mu.Unlock()

	if applied {
		return !policy.AllowOutbound, nil
	}

	output, err := lc.runOutput(ctx, sandboxName, "sudo iptables -L OUTPUT -n")
	if err != nil {
		return false, fmt.Errorf("check iptables: %w", err)
	}
	return strings.Contains(output, "DROP"), nil
}

// CurrentPolicy returns the last applied network policy for the given sandbox,
// or false if none has been applied yet.
func (lc *LimaController) CurrentPolicy(sandboxName string) (api.NetworkPolicy, bool) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	policy, ok := lc.policies[sandboxName]
	return policy, ok
}

// RemovePolicy removes the tracked policy for a sandbox from memory.
// This should be called when a sandbox is destroyed to prevent memory leaks.
func (lc *LimaController) RemovePolicy(_ context.Context, sandboxName string) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	delete(lc.policies, sandboxName)
	return nil
}

// limactlRunExec executes a command inside a Lima VM via limactl shell.
// stdout/stderr go to real tempfiles rather than bytes.Buffer so that the
// background ssh ControlMaster process Lima spawns cannot pin cmd.Wait by
// holding a copier-pipe fd open after the shell command exits.
func limactlRunExec(ctx context.Context, vmName, cmd string) error {
	limactl, err := exec.LookPath("limactl")
	if err != nil {
		return fmt.Errorf("limactl not found in PATH: %w", err)
	}
	_, stderrStr, err := runLimactlFiles(ctx, limactl, "shell", "--workdir", "/", vmName, "--", "bash", "-c", cmd)
	if err != nil {
		return fmt.Errorf("limactl exec in %s: %w: %s", vmName, err, strings.TrimSpace(stderrStr))
	}
	return nil
}

// limactlOutputExec executes a command inside a Lima VM via limactl shell and returns the output.
func limactlOutputExec(ctx context.Context, vmName, cmd string) (string, error) {
	limactl, err := exec.LookPath("limactl")
	if err != nil {
		return "", fmt.Errorf("limactl not found in PATH: %w", err)
	}
	stdoutStr, stderrStr, err := runLimactlFiles(ctx, limactl, "shell", "--workdir", "/", vmName, "--", "bash", "-c", cmd)
	if err != nil {
		return stdoutStr, fmt.Errorf("limactl exec in %s: %w: %s", vmName, err, strings.TrimSpace(stderrStr))
	}
	return stdoutStr, nil
}

// runLimactlFiles runs limactl with stdout/stderr redirected to tempfiles
// instead of bytes.Buffer. See the comment on LimaProvider.runCmd for why
// this matters (ssh ControlMaster inherits fds and pins pipe copiers).
// A timeout is enforced so a stuck ssh ControlMaster or xtables lock does
// not freeze the whole setup flow; the returned error clearly indicates
// the timeout so the caller can surface it instead of hanging.
func runLimactlFiles(ctx context.Context, limactl string, args ...string) (string, string, error) {
	stdoutFile, err := os.CreateTemp("", "airlock-net-stdout-*")
	if err != nil {
		return "", "", fmt.Errorf("create stdout temp: %w", err)
	}
	defer os.Remove(stdoutFile.Name())
	defer stdoutFile.Close()

	stderrFile, err := os.CreateTemp("", "airlock-net-stderr-*")
	if err != nil {
		return "", "", fmt.Errorf("create stderr temp: %w", err)
	}
	defer os.Remove(stderrFile.Name())
	defer stderrFile.Close()

	callCtx, cancel := context.WithTimeout(ctx, limactlCallTimeout)
	defer cancel()

	c := exec.CommandContext(callCtx, limactl, args...)
	c.Stdout = stdoutFile
	c.Stderr = stderrFile
	runErr := c.Run()

	stdoutBytes, _ := os.ReadFile(stdoutFile.Name())
	stderrBytes, _ := os.ReadFile(stderrFile.Name())

	if runErr != nil && callCtx.Err() == context.DeadlineExceeded {
		return string(stdoutBytes), string(stderrBytes), fmt.Errorf("limactl call timed out after %s (likely ssh ControlMaster or xtables lock is stuck): %w", limactlCallTimeout, runErr)
	}
	return string(stdoutBytes), string(stderrBytes), runErr
}
