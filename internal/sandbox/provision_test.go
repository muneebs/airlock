package sandbox

import (
	"context"
	"testing"

	"github.com/muneebs/airlock/internal/api"
)

// TestProvisionOptionsForRuntime covers the pure runtime→options mapping: only
// the node runtime requests Node.js; every other runtime provisions the
// baseline alone (AC3, and the "baseline for all" guarantee behind AC1).
func TestProvisionOptionsForRuntime(t *testing.T) {
	tests := []struct {
		runtime     api.RuntimeType
		wantNode    bool
		wantBun     bool
		wantDocker  bool
		wantVersion int
	}{
		{api.RuntimeNode, true, false, false, 0},
		{api.RuntimeGo, false, false, false, 0},
		{api.RuntimeRust, false, false, false, 0},
		{api.RuntimePython, false, false, false, 0},
		{api.RuntimeUnknown, false, false, false, 0},
	}
	for _, tt := range tests {
		t.Run(string(tt.runtime), func(t *testing.T) {
			got := provisionOptionsForRuntime(tt.runtime)
			if got.InstallNode != tt.wantNode {
				t.Errorf("InstallNode = %v, want %v", got.InstallNode, tt.wantNode)
			}
			if got.InstallBun != tt.wantBun {
				t.Errorf("InstallBun = %v, want %v", got.InstallBun, tt.wantBun)
			}
			if got.InstallDocker != tt.wantDocker {
				t.Errorf("InstallDocker = %v, want %v", got.InstallDocker, tt.wantDocker)
			}
			if got.NodeVersion != tt.wantVersion {
				t.Errorf("NodeVersion = %d, want %d (0 lets ProvisionSteps default)", got.NodeVersion, tt.wantVersion)
			}
		})
	}
}

// TestCreateProvisionsNodeRuntime asserts the sandbox path (Provision:true)
// invokes the shared provisioner exactly once, and requests Node when the
// resolved runtime is node (AC1 baseline runs, AC3 node requested).
func TestCreateProvisionsNodeRuntime(t *testing.T) {
	mgr, _, _, provisioner := newProvisionTestManager(t)

	spec := api.SandboxSpec{
		Name:    "prov-node",
		Runtime: "node",
		Profile: "dev",
		CPU:     intPtr(2),
	}
	if _, err := mgr.CreateWithOptions(context.Background(), spec, api.CreateOptions{Provision: true}); err != nil {
		t.Fatalf("CreateWithOptions() error: %v", err)
	}

	if len(provisioner.calls) != 1 {
		t.Fatalf("expected exactly 1 ProvisionVM call, got %d", len(provisioner.calls))
	}
	call := provisioner.calls[0]
	if call.name != "prov-node" {
		t.Errorf("provisioned name = %q, want prov-node", call.name)
	}
	if !call.opts.InstallNode {
		t.Error("expected InstallNode:true for node runtime")
	}
}

// TestCreateProvisionsNonNodeRuntime asserts a non-node runtime still provisions
// (baseline: airlock user, sudo, /home/airlock) but does not request Node.
func TestCreateProvisionsNonNodeRuntime(t *testing.T) {
	mgr, _, _, provisioner := newProvisionTestManager(t)

	spec := api.SandboxSpec{
		Name:    "prov-go",
		Runtime: "go",
		Profile: "dev",
		CPU:     intPtr(2),
	}
	if _, err := mgr.CreateWithOptions(context.Background(), spec, api.CreateOptions{Provision: true}); err != nil {
		t.Fatalf("CreateWithOptions() error: %v", err)
	}

	if len(provisioner.calls) != 1 {
		t.Fatalf("expected exactly 1 ProvisionVM call, got %d", len(provisioner.calls))
	}
	if provisioner.calls[0].opts.InstallNode {
		t.Error("expected InstallNode:false for go runtime")
	}
}

// TestCreateProvisionOrdering guards the load-bearing sequence (plan U2): for a
// remote source under a locking profile, provisioning must run BEFORE the git
// clone (ExecAsUser) — which runs as the airlock user the baseline creates —
// and BEFORE the network policy is applied, so a Node install has open egress.
func TestCreateProvisionOrdering(t *testing.T) {
	mgr, _, _, provisioner := newProvisionTestManager(t)

	spec := api.SandboxSpec{
		Name:    "prov-order",
		Source:  "gh:owner/repo",
		Runtime: "node",
		Profile: "cautious", // locks network after setup
		CPU:     intPtr(2),
	}
	if _, err := mgr.CreateWithOptions(context.Background(), spec, api.CreateOptions{Provision: true}); err != nil {
		t.Fatalf("CreateWithOptions() error: %v", err)
	}

	if len(provisioner.calls) != 1 {
		t.Fatalf("expected exactly 1 ProvisionVM call, got %d", len(provisioner.calls))
	}
	if got := provisioner.execAsUserAtEachCall[0]; got != 0 {
		t.Errorf("provisioning ran after %d ExecAsUser (clone) call(s); want 0 (provision must precede clone)", got)
	}
	if got := provisioner.policyAtEachCall[0]; got != 0 {
		t.Errorf("provisioning ran after %d network policy apply(s); want 0 (provision must precede network lock)", got)
	}
}

// TestCreateNoProvisionWhenUnset is the AC6 #EXPORT_CRITICAL regression: the
// setup/init shape (Provision unset, SkipNetworkPolicy:true) makes NO
// provisioner call, so the base-VM path keeps its CLI-layer provisioning
// unchanged.
func TestCreateNoProvisionWhenUnset(t *testing.T) {
	mgr, _, _, provisioner := newProvisionTestManager(t)

	spec := api.SandboxSpec{
		Name:    "no-prov",
		Runtime: "node",
		Profile: "dev",
		CPU:     intPtr(2),
	}
	if _, err := mgr.CreateWithOptions(context.Background(), spec, api.CreateOptions{SkipNetworkPolicy: true}); err != nil {
		t.Fatalf("CreateWithOptions() error: %v", err)
	}

	if len(provisioner.calls) != 0 {
		t.Fatalf("expected no ProvisionVM calls when Provision unset, got %d", len(provisioner.calls))
	}
}

// TestCreateProvisionFailureRollsBack asserts a provisioning failure tears the
// VM down and marks the record errored, matching the neighboring clone/network
// failure handling — a booted-but-unprovisioned VM is unusable.
func TestCreateProvisionFailureRollsBack(t *testing.T) {
	mgr, provider, _, provisioner := newProvisionTestManager(t)
	provisioner.err = context.DeadlineExceeded

	spec := api.SandboxSpec{
		Name:    "prov-fail",
		Runtime: "node",
		Profile: "dev",
		CPU:     intPtr(2),
	}
	_, err := mgr.CreateWithOptions(context.Background(), spec, api.CreateOptions{Provision: true})
	if err == nil {
		t.Fatal("expected error when provisioning fails")
	}

	if _, ok := provider.vms["prov-fail"]; ok {
		t.Error("expected VM to be deleted after provision failure")
	}
	info, _ := mgr.Status(context.Background(), "prov-fail")
	if info.State != api.StateErrored {
		t.Errorf("expected errored state after provision failure, got %s", info.State)
	}
}
