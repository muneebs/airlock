package network

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/muneebs/airlock/internal/api"
)

// fakeRunCmd records all commands executed and returns nil (success).
func fakeRunCmd(t *testing.T) (CommandRunner, *[]string) {
	var cmds []string
	return func(_ context.Context, _, cmd string) error {
		cmds = append(cmds, cmd)
		return nil
	}, &cmds
}

// fakeRunOutput returns a fixed output simulating locked or unlocked iptables.
func fakeRunOutput(locked bool) OutputRunner {
	return func(_ context.Context, _, _ string) (string, error) {
		if locked {
			return "Chain OUTPUT (policy ACCEPT)\nDROP   all  --  anywhere  anywhere\n", nil
		}
		return "Chain OUTPUT (policy ACCEPT)\nACCEPT all  --  anywhere  anywhere\n", nil
	}
}

func TestLockAppliesCorrectPolicy(t *testing.T) {
	runCmd, cmds := fakeRunCmd(t)
	lc := NewLimaControllerWithRunners(runCmd, fakeRunOutput(false))

	err := lc.Lock(context.Background(), "test")
	if err != nil {
		t.Fatalf("Lock() error: %v", err)
	}

	policy, applied := lc.CurrentPolicy("test")
	if !applied {
		t.Fatal("expected policy to be applied after Lock()")
	}
	if policy.AllowOutbound {
		t.Error("Lock() should set AllowOutbound=false")
	}
	if !policy.AllowDNS {
		t.Error("Lock() should set AllowDNS=true")
	}
	if !policy.AllowEstablished {
		t.Error("Lock() must set AllowEstablished=true to preserve the lima ssh reply path")
	}

	if len(*cmds) == 0 {
		t.Error("expected iptables commands to be executed")
	}

	locked, err := lc.IsLocked(context.Background(), "test")
	if err != nil {
		t.Fatalf("IsLocked() error: %v", err)
	}
	if !locked {
		t.Error("expected IsLocked()=true after Lock()")
	}
}

func TestUnlockAppliesCorrectPolicy(t *testing.T) {
	runCmd, cmds := fakeRunCmd(t)
	lc := NewLimaControllerWithRunners(runCmd, fakeRunOutput(false))

	err := lc.Unlock(context.Background(), "test")
	if err != nil {
		t.Fatalf("Unlock() error: %v", err)
	}

	policy, applied := lc.CurrentPolicy("test")
	if !applied {
		t.Fatal("expected policy to be applied after Unlock()")
	}
	if !policy.AllowOutbound {
		t.Error("Unlock() should set AllowOutbound=true")
	}
	if !policy.AllowEstablished {
		t.Error("Unlock() should set AllowEstablished=true")
	}

	if len(*cmds) == 0 {
		t.Error("expected iptables commands to be executed")
	}

	locked, err := lc.IsLocked(context.Background(), "test")
	if err != nil {
		t.Fatalf("IsLocked() error: %v", err)
	}
	if locked {
		t.Error("expected IsLocked()=false after Unlock()")
	}
}

func TestApplyPolicyCautious(t *testing.T) {
	runCmd, _ := fakeRunCmd(t)
	lc := NewLimaControllerWithRunners(runCmd, fakeRunOutput(false))

	policy := api.NetworkPolicy{
		AllowDNS:         true,
		AllowOutbound:    false,
		AllowEstablished: true,
		LockAfterSetup:   true,
	}

	err := lc.ApplyPolicy(context.Background(), "test", policy)
	if err != nil {
		t.Fatalf("ApplyPolicy() error: %v", err)
	}

	got, applied := lc.CurrentPolicy("test")
	if !applied {
		t.Fatal("expected policy to be applied")
	}
	if got.AllowOutbound {
		t.Error("cautious policy should block outbound")
	}
	if !got.AllowDNS {
		t.Error("cautious policy should allow DNS")
	}
	if !got.AllowEstablished {
		t.Error("cautious policy should allow established")
	}
	if !got.LockAfterSetup {
		t.Error("cautious policy should have LockAfterSetup=true")
	}

	locked, _ := lc.IsLocked(context.Background(), "test")
	if !locked {
		t.Error("cautious policy should result in IsLocked()=true")
	}
}

func TestNewLimaController(t *testing.T) {
	lc := NewLimaController()
	if lc == nil {
		t.Error("expected non-nil controller")
	}
}

func TestCurrentPolicyBeforeApply(t *testing.T) {
	runCmd, _ := fakeRunCmd(t)
	lc := NewLimaControllerWithRunners(runCmd, fakeRunOutput(false))
	_, applied := lc.CurrentPolicy("test")
	if applied {
		t.Error("expected no policy applied on new controller")
	}
}

func TestLockRulesetContent(t *testing.T) {
	runCmd, cmds := fakeRunCmd(t)
	lc := NewLimaControllerWithRunners(runCmd, fakeRunOutput(false))

	lc.Lock(context.Background(), "test")

	if len(*cmds) != 1 {
		t.Fatalf("expected 1 iptables-restore command, got %d", len(*cmds))
	}
	cmd := (*cmds)[0]
	if !strings.Contains(cmd, "iptables-restore") {
		t.Errorf("expected iptables-restore command, got: %s", cmd)
	}
	if !strings.Contains(cmd, ":OUTPUT DROP") {
		t.Error("lock ruleset should default OUTPUT to DROP")
	}
	if !strings.Contains(cmd, "-A OUTPUT -o lo -j ACCEPT") {
		t.Error("lock ruleset should allow loopback")
	}
	if !strings.Contains(cmd, "--dport 53 -j ACCEPT") {
		t.Error("lock ruleset should allow DNS")
	}
	if strings.Contains(cmd, "-A OUTPUT -j DROP") {
		t.Error("lock ruleset should not have explicit DROP rule — default policy handles it")
	}
}

func TestUnlockRulesetContent(t *testing.T) {
	runCmd, cmds := fakeRunCmd(t)
	lc := NewLimaControllerWithRunners(runCmd, fakeRunOutput(false))

	lc.Unlock(context.Background(), "test")

	if len(*cmds) != 1 {
		t.Fatalf("expected 1 iptables-restore command, got %d", len(*cmds))
	}
	cmd := (*cmds)[0]
	if !strings.Contains(cmd, "iptables-restore") {
		t.Errorf("expected iptables-restore command, got: %s", cmd)
	}
	if !strings.Contains(cmd, "-A OUTPUT -j ACCEPT") {
		t.Error("unlock ruleset should allow all outbound")
	}
	if !strings.Contains(cmd, "ESTABLISHED,RELATED") {
		t.Error("unlock ruleset should allow established connections")
	}
}

func TestBuildOutputRulesLockPolicy(t *testing.T) {
	policy := api.NetworkPolicy{AllowDNS: true, AllowOutbound: false, AllowEstablished: false}
	rules := BuildOutputRules(policy)

	if !strings.Contains(rules, ":OUTPUT DROP") {
		t.Error("lock ruleset should default OUTPUT to DROP")
	}
	if strings.Contains(rules, "-A OUTPUT -j DROP") {
		t.Error("lock ruleset should not have explicit DROP — default policy handles it")
	}
	if !strings.Contains(rules, "COMMIT") {
		t.Error("ruleset must end with COMMIT")
	}
}

func TestBuildOutputRulesUnlockPolicy(t *testing.T) {
	policy := api.NetworkPolicy{AllowDNS: true, AllowOutbound: true, AllowEstablished: true}
	rules := BuildOutputRules(policy)

	if !strings.Contains(rules, "-A OUTPUT -j ACCEPT") {
		t.Error("unlock ruleset should have ACCEPT all rule")
	}
	if !strings.Contains(rules, "ESTABLISHED,RELATED") {
		t.Error("unlock ruleset should allow established")
	}
}

func TestBuildOutputRulesNoDNS(t *testing.T) {
	policy := api.NetworkPolicy{AllowDNS: false, AllowOutbound: false, AllowEstablished: false}
	rules := BuildOutputRules(policy)

	if strings.Contains(rules, "--dport 53") {
		t.Error("ruleset should not contain DNS rule when AllowDNS=false")
	}
}

func TestApplyPolicyErrorPropagates(t *testing.T) {
	failCmd := func(_ context.Context, _, _ string) error {
		return fmt.Errorf("permission denied")
	}
	lc := NewLimaControllerWithRunners(failCmd, fakeRunOutput(false))

	err := lc.Lock(context.Background(), "test")
	if err == nil {
		t.Fatal("expected error from failing runner")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("expected wrapped error, got: %v", err)
	}

	_, applied := lc.CurrentPolicy("test")
	if applied {
		t.Error("policy should not be recorded after failed apply")
	}
}

func TestRemovePolicy(t *testing.T) {
	runCmd, _ := fakeRunCmd(t)
	lc := NewLimaControllerWithRunners(runCmd, fakeRunOutput(false))

	if err := lc.Lock(context.Background(), "sandbox-a"); err != nil {
		t.Fatalf("Lock(sandbox-a) error: %v", err)
	}
	if err := lc.Unlock(context.Background(), "sandbox-b"); err != nil {
		t.Fatalf("Unlock(sandbox-b) error: %v", err)
	}

	_, appliedA := lc.CurrentPolicy("sandbox-a")
	if !appliedA {
		t.Error("expected policy for sandbox-a after Lock()")
	}
	_, appliedB := lc.CurrentPolicy("sandbox-b")
	if !appliedB {
		t.Error("expected policy for sandbox-b after Unlock()")
	}

	if err := lc.RemovePolicy(context.Background(), "sandbox-a"); err != nil {
		t.Fatalf("RemovePolicy error: %v", err)
	}
	_, appliedA = lc.CurrentPolicy("sandbox-a")
	if appliedA {
		t.Error("expected no policy for sandbox-a after RemovePolicy()")
	}

	_, appliedB = lc.CurrentPolicy("sandbox-b")
	if !appliedB {
		t.Error("sandbox-b policy should be unaffected by removing sandbox-a")
	}
}
