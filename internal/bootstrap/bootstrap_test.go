package bootstrap

import (
	"testing"

	"github.com/muneebs/airlock/internal/api"
)

// TestAssembleWiresAllInterfaces guards the DI contract: every exported
// field on Dependencies must be non-nil after Assemble so the cli layer
// never sees a nil interface (PRINCIPLES.md §5 DIP).
func TestAssembleWiresAllInterfaces(t *testing.T) {
	deps, err := Assemble()
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	checks := []struct {
		name string
		val  any
	}{
		{"Manager", deps.Manager},
		{"Provider", deps.Provider},
		{"Provisioner", deps.Provisioner},
		{"Sheller", deps.Sheller},
		{"Mounts", deps.Mounts},
		{"Network", deps.Network},
		{"Profiles", deps.Profiles},
		{"Detector", deps.Detector},
	}
	for _, c := range checks {
		if c.val == nil {
			t.Errorf("%s is nil", c.name)
		}
	}
	if deps.ConfigDir == "" {
		t.Error("ConfigDir is empty")
	}
}

// TestAssembleInterfaceTypes pins the interface return types so a future
// refactor cannot silently narrow the contract (LSP).
func TestAssembleInterfaceTypes(t *testing.T) {
	deps, err := Assemble()
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	var (
		_ api.SandboxManager    = deps.Manager
		_ api.Provider          = deps.Provider
		_ api.Provisioner       = deps.Provisioner
		_ api.ShellProvider     = deps.Sheller
		_ api.MountManager      = deps.Mounts
		_ api.NetworkController = deps.Network
		_ api.ProfileRegistry   = deps.Profiles
		_ api.RuntimeDetector   = deps.Detector
	)
}
