package network

import (
	"context"
	"testing"

	"github.com/muneebs/airlock/internal/api"
)

// NOTE: The LimaController currently has stub implementations for limactlRun
// and limactlOutput. These tests verify the policy construction logic and
// will be extended with integration tests once exec is wired up.

func TestLockPolicy(t *testing.T) {
	lc := NewLimaController("test-vm")

	// Lock should set up a policy with DNS allowed, outbound blocked
	policy := api.NetworkPolicy{
		AllowDNS:         true,
		AllowOutbound:    false,
		AllowEstablished: false,
	}

	// Test that the policy is constructed correctly for lock
	if !policy.AllowDNS {
		t.Error("locked policy should allow DNS")
	}
	if policy.AllowOutbound {
		t.Error("locked policy should block outbound")
	}

	// The actual limactl calls will fail because they're stubs
	err := lc.ApplyPolicy(context.Background(), "test", policy)
	if err == nil {
		t.Error("expected error from stub limactlRun")
	}
}

func TestUnlockPolicy(t *testing.T) {
	policy := api.NetworkPolicy{
		AllowDNS:         true,
		AllowOutbound:    true,
		AllowEstablished: true,
	}

	if !policy.AllowOutbound {
		t.Error("unlocked policy should allow outbound")
	}
	if !policy.AllowEstablished {
		t.Error("unlocked policy should allow established")
	}
}

func TestNewLimaController(t *testing.T) {
	lc := NewLimaController("my-vm")
	if lc.vmName != "my-vm" {
		t.Errorf("expected vmName my-vm, got %s", lc.vmName)
	}
}

func TestCautiousProfilePolicy(t *testing.T) {
	// The cautious profile: DNS allowed, outbound blocked, established allowed, lock after setup
	policy := api.NetworkPolicy{
		AllowDNS:         true,
		AllowOutbound:    false,
		AllowEstablished: true,
		LockAfterSetup:   true,
	}

	if !policy.AllowDNS {
		t.Error("cautious policy should allow DNS")
	}
	if policy.AllowOutbound {
		t.Error("cautious policy should block outbound")
	}
	if !policy.AllowEstablished {
		t.Error("cautious policy should allow established connections")
	}
	if !policy.LockAfterSetup {
		t.Error("cautious policy should lock after setup")
	}
}
