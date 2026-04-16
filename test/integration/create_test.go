package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/muneebs/airlock/internal/api"
)

func TestCreateBasicSandbox(t *testing.T) {
	h := newHarness(t)

	spec := api.SandboxSpec{
		Name:    "myproject",
		Profile: "cautious",
		CPU:     intPtr(2),
		Memory:  "4GiB",
		Disk:    "20GiB",
	}

	h.createVMFiles(t, "myproject")

	info, err := h.Manager.Create(h.ctx(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if info.Name != "myproject" {
		t.Errorf("expected name myproject, got %s", info.Name)
	}
	if info.State != api.StateRunning {
		t.Errorf("expected state running, got %s", info.State)
	}
	if info.Profile != "cautious" {
		t.Errorf("expected profile cautious, got %s", info.Profile)
	}

	calls := h.calls()
	foundCreate := false
	foundStart := false
	for _, c := range calls {
		if strings.Contains(c, "create") && strings.Contains(c, "myproject") {
			foundCreate = true
		}
		if strings.Contains(c, "start") && strings.Contains(c, "myproject") {
			foundStart = true
		}
	}
	if !foundCreate {
		t.Error("expected limactl create call for myproject")
	}
	if !foundStart {
		t.Error("expected limactl start call for myproject")
	}
}

func TestCreateWithSource(t *testing.T) {
	h := newHarness(t)

	projectDir := filepath.Join(h.tmpDir, "myapp")
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}

	h.createVMFiles(t, "myapp")

	spec := api.SandboxSpec{
		Name:    "myapp",
		Source:  projectDir,
		Profile: "dev",
		CPU:     intPtr(2),
	}

	info, err := h.Manager.Create(h.ctx(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if info.Source != projectDir {
		t.Errorf("expected source %s, got %s", projectDir, info.Source)
	}

	mounts, err := h.Mounts.List(h.ctx(), "myapp")
	if err != nil {
		t.Fatalf("List mounts error: %v", err)
	}
	if len(mounts) == 0 {
		t.Error("expected mount to be registered when Source is set")
	}
}

func TestCreateCautiousLocksNetwork(t *testing.T) {
	h := newHarness(t)

	h.createVMFiles(t, "locked-sandbox")

	spec := api.SandboxSpec{
		Name:    "locked-sandbox",
		Profile: "cautious",
		CPU:     intPtr(2),
	}

	_, err := h.Manager.Create(h.ctx(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	locked, err := h.Network.IsLocked(h.ctx(), "locked-sandbox")
	if err != nil {
		t.Fatalf("IsLocked() error: %v", err)
	}
	if !locked {
		t.Error("cautious profile should lock network after setup")
	}

	calls := h.calls()
	foundIptables := false
	for _, c := range calls {
		if strings.Contains(c, "iptables-restore") {
			foundIptables = true
		}
	}
	if !foundIptables {
		t.Error("cautious profile should apply iptables rules via iptables-restore")
	}
}

func TestCreateDevDoesNotLockNetwork(t *testing.T) {
	h := newHarness(t)

	h.createVMFiles(t, "dev-sandbox")

	spec := api.SandboxSpec{
		Name:    "dev-sandbox",
		Profile: "dev",
		CPU:     intPtr(2),
	}

	_, err := h.Manager.Create(h.ctx(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	locked, err := h.Network.IsLocked(h.ctx(), "dev-sandbox")
	if err != nil {
		t.Fatalf("IsLocked() error: %v", err)
	}
	if locked {
		t.Error("dev profile should not lock network")
	}
}

func TestCreateDuplicateFails(t *testing.T) {
	h := newHarness(t)

	h.createVMFiles(t, "dupe")

	spec := api.SandboxSpec{
		Name:    "dupe",
		Profile: "cautious",
		CPU:     intPtr(2),
	}

	_, err := h.Manager.Create(h.ctx(), spec)
	if err != nil {
		t.Fatalf("first Create() error: %v", err)
	}

	_, err = h.Manager.Create(h.ctx(), spec)
	if err == nil {
		t.Error("expected error creating duplicate sandbox")
	}
}

func TestCreateEmptyNameFails(t *testing.T) {
	h := newHarness(t)

	spec := api.SandboxSpec{
		Name:    "",
		Profile: "cautious",
		CPU:     intPtr(2),
	}

	_, err := h.Manager.Create(h.ctx(), spec)
	if err == nil {
		t.Error("expected error for empty name")
	}
}
