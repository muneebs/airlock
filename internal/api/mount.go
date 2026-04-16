package api

import "context"

// Mount describes a directory mapped between host and sandbox.
type Mount struct {
	Name     string `json:"name" yaml:"name" toml:"name"`
	HostPath string `json:"host_path" yaml:"host_path" toml:"host_path"`
	VMPath   string `json:"vm_path" yaml:"vm_path" toml:"vm_path"`
	Writable bool   `json:"writable" yaml:"writable" toml:"writable"`
	Inotify  bool   `json:"inotify" yaml:"inotify" toml:"inotify"`
}

// MountManager registers and tracks host directories mounted into sandboxes.
type MountManager interface {
	Register(ctx context.Context, sandboxName string, mount Mount) error
	Unregister(ctx context.Context, sandboxName string, name string) error
	List(ctx context.Context, sandboxName string) ([]Mount, error)
	Apply(ctx context.Context, sandboxName string) error
}
