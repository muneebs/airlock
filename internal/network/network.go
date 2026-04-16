// Package network provides iptables-based network isolation for Lima VMs.
// It shells out to limactl to run iptables commands inside the sandbox VM,
// controlling whether the sandbox can make outbound connections.
package network

import (
	"context"
	"fmt"
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
type LimaController struct {
	vmName    string
	runCmd    CommandRunner
	runOutput OutputRunner
	mu        sync.Mutex
	policy    api.NetworkPolicy
	applied   bool
}

// NewLimaController creates a network controller for the given VM name
// using the default (production) limactl runners.
func NewLimaController(vmName string) *LimaController {
	return &LimaController{
		vmName:    vmName,
		runCmd:    limactlRunExec,
		runOutput: limactlOutputExec,
	}
}

// NewLimaControllerWithRunners creates a network controller with injectable
// command runners, for testing.
func NewLimaControllerWithRunners(vmName string, runCmd CommandRunner, runOutput OutputRunner) *LimaController {
	return &LimaController{
		vmName:    vmName,
		runCmd:    runCmd,
		runOutput: runOutput,
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
func (lc *LimaController) ApplyPolicy(ctx context.Context, sandboxName string, policy api.NetworkPolicy) error {
	ruleset := buildOutputRules(policy)
	cmd := fmt.Sprintf("printf '%%s' '%s' | sudo iptables-restore", ruleset)

	if err := lc.runCmd(ctx, lc.vmName, cmd); err != nil {
		return fmt.Errorf("apply iptables policy: %w", err)
	}

	lc.mu.Lock()
	lc.policy = policy
	lc.applied = true
	lc.mu.Unlock()

	return nil
}

// buildOutputRules constructs an iptables-restore format ruleset for the
// OUTPUT chain based on the given policy. The ruleset replaces the OUTPUT
// chain atomically — either all rules apply or none do.
func buildOutputRules(policy api.NetworkPolicy) string {
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
	if lc.applied {
		locked := !lc.policy.AllowOutbound
		lc.mu.Unlock()
		return locked, nil
	}
	lc.mu.Unlock()

	output, err := lc.runOutput(ctx, lc.vmName, "sudo iptables -L OUTPUT -n")
	if err != nil {
		return false, fmt.Errorf("check iptables: %w", err)
	}
	return strings.Contains(output, "DROP"), nil
}

// CurrentPolicy returns the last applied network policy, or false if none
// has been applied yet.
func (lc *LimaController) CurrentPolicy() (api.NetworkPolicy, bool) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.policy, lc.applied
}

// limactlRunExec executes a command inside a Lima VM.
// Not yet wired to exec.CommandContext — returns an error for now.
func limactlRunExec(ctx context.Context, vmName, cmd string) error {
	return fmt.Errorf("limactlRun: not yet wired to exec")
}

// limactlOutputExec executes a command inside a Lima VM and returns the output.
// Not yet wired to exec.CommandContext — returns an error for now.
func limactlOutputExec(ctx context.Context, vmName, cmd string) (string, error) {
	return "", fmt.Errorf("limactlOutput: not yet wired to exec")
}
