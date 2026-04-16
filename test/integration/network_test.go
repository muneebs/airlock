package integration

import (
	"os"
	"strings"
	"testing"

	"github.com/muneebs/airlock/internal/api"
	"github.com/muneebs/airlock/internal/network"
)

func TestNetworkLockBlocksOutbound(t *testing.T) {
	h := newHarness(t)
	h.createVMFiles(t, "net-lock")

	spec := api.SandboxSpec{
		Name:    "net-lock",
		Profile: "strict",
		CPU:     intPtr(2),
	}

	_, err := h.Manager.Create(h.ctx(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	locked, err := h.Network.IsLocked(h.ctx(), "net-lock")
	if err != nil {
		t.Fatalf("IsLocked() error: %v", err)
	}
	if !locked {
		t.Error("strict profile should lock network")
	}

	policy, applied := h.Network.CurrentPolicy("net-lock")
	if !applied {
		t.Fatal("expected policy to be applied")
	}
	if policy.AllowOutbound {
		t.Error("locked policy should not allow outbound")
	}
	if !policy.AllowDNS {
		t.Error("locked policy should allow DNS")
	}

	hasIptables := false
	for _, c := range strings.Split(h.rawCallLog(), "\n") {
		if strings.Contains(c, "iptables-restore") {
			hasIptables = true
		}
	}
	if !hasIptables {
		t.Error("expected iptables-restore call")
	}
}

func TestNetworkUnlockAllowsOutbound(t *testing.T) {
	h := newHarness(t)
	h.createVMFiles(t, "net-unlock")

	spec := api.SandboxSpec{
		Name:    "net-unlock",
		Profile: "dev",
		CPU:     intPtr(2),
	}

	_, err := h.Manager.Create(h.ctx(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if err := h.Network.Lock(h.ctx(), "net-unlock"); err != nil {
		t.Fatalf("Lock() error: %v", err)
	}
	if err := h.Network.Unlock(h.ctx(), "net-unlock"); err != nil {
		t.Fatalf("Unlock() error: %v", err)
	}

	locked, err := h.Network.IsLocked(h.ctx(), "net-unlock")
	if err != nil {
		t.Fatalf("IsLocked() error: %v", err)
	}
	if locked {
		t.Error("network should be unlocked after Unlock()")
	}

	policy, applied := h.Network.CurrentPolicy("net-unlock")
	if !applied {
		t.Fatal("expected policy to be applied")
	}
	if !policy.AllowOutbound {
		t.Error("unlocked policy should allow outbound")
	}
	if !policy.AllowEstablished {
		t.Error("unlocked policy should allow established")
	}
}

func TestNetworkPolicyIsolation(t *testing.T) {
	h := newHarness(t)
	h.createVMFiles(t, "iso-a")
	h.createVMFiles(t, "iso-b")

	specA := api.SandboxSpec{Name: "iso-a", Profile: "dev", CPU: intPtr(2)}
	specB := api.SandboxSpec{Name: "iso-b", Profile: "strict", CPU: intPtr(2)}

	_, err := h.Manager.Create(h.ctx(), specA)
	if err != nil {
		t.Fatalf("Create iso-a error: %v", err)
	}
	_, err = h.Manager.Create(h.ctx(), specB)
	if err != nil {
		t.Fatalf("Create iso-b error: %v", err)
	}

	lockedA, err := h.Network.IsLocked(h.ctx(), "iso-a")
	if err != nil {
		t.Fatalf("IsLocked(iso-a) error: %v", err)
	}
	lockedB, err := h.Network.IsLocked(h.ctx(), "iso-b")
	if err != nil {
		t.Fatalf("IsLocked(iso-b) error: %v", err)
	}

	if lockedA {
		t.Error("dev sandbox should be unlocked")
	}
	if !lockedB {
		t.Error("strict sandbox should be locked")
	}
}

func TestNetworkRemovePolicyOnDestroy(t *testing.T) {
	h := newHarness(t)
	h.createVMFiles(t, "net-destroy")

	spec := api.SandboxSpec{
		Name:    "net-destroy",
		Profile: "cautious",
		CPU:     intPtr(2),
	}

	_, err := h.Manager.Create(h.ctx(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if err := h.Manager.Destroy(h.ctx(), "net-destroy"); err != nil {
		t.Fatalf("Destroy() error: %v", err)
	}

	_, applied := h.Network.CurrentPolicy("net-destroy")
	if applied {
		t.Error("policy should be removed after destroy")
	}
}

func TestBuildOutputRulesContent(t *testing.T) {
	policy := api.NetworkPolicy{
		AllowDNS:         true,
		AllowOutbound:    false,
		AllowEstablished: true,
	}

	rules := network.BuildOutputRules(policy)

	if !strings.Contains(rules, "*filter") {
		t.Error("ruleset should start with *filter")
	}
	if !strings.Contains(rules, ":OUTPUT DROP") {
		t.Error("locked ruleset should have OUTPUT DROP policy")
	}
	if !strings.Contains(rules, "COMMIT") {
		t.Error("ruleset should end with COMMIT")
	}
	if strings.Contains(rules, "-A OUTPUT -j ACCEPT") {
		t.Error("locked ruleset should not have ACCEPT all rule")
	}
}

func TestLockUnlockRulesets(t *testing.T) {
	lockRules := network.BuildOutputRules(api.NetworkPolicy{
		AllowDNS: true, AllowOutbound: false, AllowEstablished: false,
	})
	if !strings.Contains(lockRules, ":OUTPUT DROP") {
		t.Error("lock ruleset should default OUTPUT to DROP")
	}
	if strings.Contains(lockRules, "-A OUTPUT -j ACCEPT") {
		t.Error("lock ruleset should not allow all outbound")
	}
	if !strings.Contains(lockRules, "--dport 53 -j ACCEPT") {
		t.Error("lock ruleset should allow DNS")
	}
	if !strings.Contains(lockRules, "-A OUTPUT -o lo -j ACCEPT") {
		t.Error("lock ruleset should allow loopback")
	}

	unlockRules := network.BuildOutputRules(api.NetworkPolicy{
		AllowDNS: true, AllowOutbound: true, AllowEstablished: true,
	})
	if !strings.Contains(unlockRules, "-A OUTPUT -j ACCEPT") {
		t.Error("unlock ruleset should allow all outbound")
	}
	if !strings.Contains(unlockRules, "ESTABLISHED,RELATED") {
		t.Error("unlock ruleset should allow established")
	}
	if !strings.Contains(unlockRules, "--dport 53 -j ACCEPT") {
		t.Error("unlock ruleset should allow DNS")
	}
}

func (h *harness) rawCallLog() string {
	data, err := os.ReadFile(h.callLog)
	if err != nil {
		return ""
	}
	return string(data)
}
