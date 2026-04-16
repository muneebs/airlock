// Package network provides iptables-based network isolation for Lima VMs.
// It shells out to limactl to run iptables commands inside the sandbox VM,
// controlling whether the sandbox can make outbound connections.
package network

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/muneebs/airlock/internal/api"
)

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

// Lock blocks all outbound network traffic except DNS and loopback.
// After this call, the sandbox can only resolve DNS and communicate on loopback.
func (lc *LimaController) Lock(ctx context.Context, sandboxName string) error {
	policy := api.NetworkPolicy{
		AllowDNS:         true,
		AllowOutbound:    false,
		AllowEstablished: false,
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
func limactlRunExec(ctx context.Context, vmName, cmd string) error {
	limactl, err := exec.LookPath("limactl")
	if err != nil {
		return fmt.Errorf("limactl not found in PATH: %w", err)
	}
	c := exec.CommandContext(ctx, limactl, "shell", "--workdir", "/", vmName, "--", "bash", "-c", cmd)
	var stderr bytes.Buffer
	c.Stdout = nil
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("limactl exec in %s: %w: %s", vmName, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// limactlOutputExec executes a command inside a Lima VM via limactl shell and returns the output.
func limactlOutputExec(ctx context.Context, vmName, cmd string) (string, error) {
	limactl, err := exec.LookPath("limactl")
	if err != nil {
		return "", fmt.Errorf("limactl not found in PATH: %w", err)
	}
	c := exec.CommandContext(ctx, limactl, "shell", "--workdir", "/", vmName, "--", "bash", "-c", cmd)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	output, err := c.Output()
	if err != nil {
		return string(output), fmt.Errorf("limactl exec in %s: %w: %s", vmName, err, strings.TrimSpace(stderr.String()))
	}
	return string(output), nil
}
