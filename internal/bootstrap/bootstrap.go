// Package bootstrap wires concrete implementations (Lima VM provider, iptables
// network controller, JSON mount store, sandbox manager) into the api
// interfaces the CLI consumes. Keeping this assembly in its own package is what
// lets the cli package stay free of concrete backend imports — satisfying the
// Dependency Inversion rule in PRINCIPLES.md §5.
package bootstrap

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/muneebs/airlock/internal/api"
	"github.com/muneebs/airlock/internal/detect"
	"github.com/muneebs/airlock/internal/mount"
	"github.com/muneebs/airlock/internal/network"
	"github.com/muneebs/airlock/internal/profile"
	"github.com/muneebs/airlock/internal/sandbox"
	"github.com/muneebs/airlock/internal/vm/lima"
)

// Dependencies carries the fully-wired interface values the CLI needs.
// All fields are api-package interface types — the CLI never sees concrete
// backend types.
type Dependencies struct {
	Manager     api.SandboxManager
	Provider    api.Provider
	Provisioner api.Provisioner
	Sheller     api.ShellProvider
	Mounts      api.MountManager
	Network     api.NetworkController
	Profiles    api.ProfileRegistry
	Detector    api.RuntimeDetector
	ConfigDir   string
}

// Assemble constructs the default production dependency graph.
func Assemble() (*Dependencies, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}
	configDir := filepath.Join(home, ".airlock")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}

	limaProvider, err := lima.NewLimaProvider()
	if err != nil {
		return nil, fmt.Errorf("init lima provider: %w", err)
	}

	detector := detect.NewCompositeDetector()
	profiles := profile.NewRegistry()

	mountStore, err := mount.NewJSONStore(filepath.Join(configDir, "mounts.json"))
	if err != nil {
		return nil, fmt.Errorf("init mount store: %w", err)
	}

	networkCtrl := network.NewLimaController()
	storePath := filepath.Join(configDir, "sandboxes.json")

	mgr, err := sandbox.NewManager(
		limaProvider,
		limaProvider,
		detector,
		profiles,
		mountStore,
		networkCtrl,
		storePath,
	)
	if err != nil {
		return nil, fmt.Errorf("init sandbox manager: %w", err)
	}

	return &Dependencies{
		Manager:     mgr,
		Provider:    limaProvider,
		Provisioner: limaProvider,
		Sheller:     limaProvider,
		Mounts:      mountStore,
		Network:     networkCtrl,
		Profiles:    profiles,
		Detector:    detector,
		ConfigDir:   configDir,
	}, nil
}
