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
	Exec(ctx context.Context, name string, cmd []string) (string, error)
	ExecAsUser(ctx context.Context, name, user string, cmd []string) (string, error)
	CopyToVM(ctx context.Context, name, src, dst string) error
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
}

// VMMount describes a host directory to mount inside the VM.
type VMMount struct {
	HostPath  string `json:"host_path" yaml:"host_path"`
	GuestPath string `json:"guest_path" yaml:"guest_path"`
	Writable  bool   `json:"writable" yaml:"writable"`
	Inotify   bool   `json:"inotify" yaml:"inotify"`
}
