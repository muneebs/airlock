package api

import "context"

// Provider abstracts VM lifecycle management. The Lima implementation
// shells out to limactl; future implementations could use libvirt,
// Firecracker, or cloud APIs.
type Provider interface {
	Create(ctx context.Context, spec VMSpec) error
	Start(ctx context.Context, name string) error
	Stop(ctx context.Context, name string) error
	Delete(ctx context.Context, name string) error
	Exists(ctx context.Context, name string) (bool, error)
	IsRunning(ctx context.Context, name string) (bool, error)
	// Status returns the provider-native lifecycle string for the VM
	// (e.g. "Running", "Stopped", "Broken"). Returns an empty string if
	// the VM does not exist. Used to surface live progress during slow
	// operations like first-boot; not for authoritative state decisions.
	Status(ctx context.Context, name string) (string, error)
	Exec(ctx context.Context, name string, cmd []string) (string, error)
	ExecAsUser(ctx context.Context, name, user string, cmd []string) (string, error)
	CopyToVM(ctx context.Context, name, src, dst string) error
}

// Provisioner handles VM provisioning and snapshot management for setup/reset.
// This is a separate interface from Provider following the Interface Segregation
// Principle — not every Provider can provision VMs or take snapshots.
type Provisioner interface {
	ProvisionVM(ctx context.Context, name string, nodeVersion int) error
	ProvisionSteps(name string, nodeVersion int) []ProvisionStep
	SnapshotClean(ctx context.Context, name string) error
	HasCleanSnapshot(ctx context.Context, name string) (bool, error)
}

// ProvisionStep is a named unit of work in the provisioning sequence.
// Callers (e.g. the setup command) iterate these to render branded,
// per-step progress instead of a single opaque "Provisioning" phase.
type ProvisionStep struct {
	Label string
	Run   func(ctx context.Context) error
}

// ShellProvider provides interactive shell access to a VM. This is a separate
// interface because not all providers support interactive TTY access.
type ShellProvider interface {
	Shell(ctx context.Context, name string) error
}

// VMSpec describes a virtual machine to create.
type VMSpec struct {
	Name   string    `json:"name" yaml:"name"`
	OS     string    `json:"os" yaml:"os"`
	Arch   string    `json:"arch" yaml:"arch"`
	CPU    int       `json:"cpu" yaml:"cpu"`
	Memory string    `json:"memory" yaml:"memory"`
	Disk   string    `json:"disk" yaml:"disk"`
	Mounts []VMMount `json:"mounts" yaml:"mounts"`
	Ports  string    `json:"ports,omitempty" yaml:"ports,omitempty"`

	// ProvisionCmds run once after first boot.
	ProvisionCmds []string `json:"provision_cmds" yaml:"provision_cmds"`

	// StartAtLogin starts the VM automatically when the user logs in.
	StartAtLogin bool `json:"start_at_login,omitempty" yaml:"start_at_login,omitempty"`
}

// VMMount describes a host directory to mount inside the VM.
type VMMount struct {
	HostPath  string `json:"host_path" yaml:"host_path"`
	GuestPath string `json:"guest_path" yaml:"guest_path"`
	Writable  bool   `json:"writable" yaml:"writable"`
	Inotify   bool   `json:"inotify" yaml:"inotify"`
}
