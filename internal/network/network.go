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

// LimaController manages network isolation by executing iptables commands
// inside a Lima VM via limactl. It implements api.NetworkController.
type LimaController struct {
	vmName  string
	mu      sync.Mutex
	policy  api.NetworkPolicy
	applied bool
}

// NewLimaController creates a network controller for the given VM name.
func NewLimaController(vmName string) *LimaController {
	return &LimaController{vmName: vmName}
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
// It records the applied policy for inspection via CurrentPolicy().
// LockAfterSetup in the policy is not consumed here — the sandbox orchestrator
// reads it to decide whether to call Lock() after setup completes.
func (lc *LimaController) ApplyPolicy(ctx context.Context, sandboxName string, policy api.NetworkPolicy) error {
	vmName := lc.vmName

	// Flush existing OUTPUT rules
	if err := limactlRun(ctx, vmName, "sudo iptables -F OUTPUT"); err != nil {
		return fmt.Errorf("flush iptables OUTPUT: %w", err)
	}

	// Always allow loopback
	if err := limactlRun(ctx, vmName, "sudo iptables -A OUTPUT -o lo -j ACCEPT"); err != nil {
		return fmt.Errorf("allow loopback: %w", err)
	}

	// DNS (UDP port 53)
	if policy.AllowDNS {
		if err := limactlRun(ctx, vmName, "sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT"); err != nil {
			return fmt.Errorf("allow DNS: %w", err)
		}
	}

	// Established connections
	if policy.AllowEstablished {
		if err := limactlRun(ctx, vmName, "sudo iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"); err != nil {
			return fmt.Errorf("allow established: %w", err)
		}
	}

	// Full outbound
	if policy.AllowOutbound {
		if err := limactlRun(ctx, vmName, "sudo iptables -A OUTPUT -j ACCEPT"); err != nil {
			return fmt.Errorf("allow outbound: %w", err)
		}
	} else {
		// Drop everything else
		if err := limactlRun(ctx, vmName, "sudo iptables -A OUTPUT -j DROP"); err != nil {
			return fmt.Errorf("drop outbound: %w", err)
		}
	}

	lc.mu.Lock()
	lc.policy = policy
	lc.applied = true
	lc.mu.Unlock()

	return nil
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

	output, err := limactlOutput(ctx, lc.vmName, "sudo iptables -L OUTPUT -n")
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

// limactlRun executes a command inside a Lima VM.
func limactlRun(ctx context.Context, vmName, cmd string) error {
	// In production, this shells out to:
	// limactl shell --workdir / <vmName> -- <cmd...>
	// For now, this is a stub that will be wired to exec.CommandContext.
	return fmt.Errorf("limactlRun: not yet wired to exec")
}

// limactlOutput executes a command inside a Lima VM and returns the output.
func limactlOutput(ctx context.Context, vmName, cmd string) (string, error) {
	// In production, this shells out to limactl and captures output.
	return "", fmt.Errorf("limactlOutput: not yet wired to exec")
}
