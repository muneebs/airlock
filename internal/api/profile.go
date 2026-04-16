package api

// MountPolicy controls how host directories are exposed to the sandbox.
type MountPolicy struct {
	Writable        bool `json:"writable" yaml:"writable" toml:"writable"`
	AllowHostMounts bool `json:"allow_host_mounts" yaml:"allow_host_mounts" toml:"allow_host_mounts"`
}

// DockerPolicy controls Docker access within a sandbox.
type DockerPolicy struct {
	Allowed        bool `json:"allowed" yaml:"allowed" toml:"allowed"`
	ReadOnlySocket bool `json:"read_only_socket" yaml:"read_only_socket" toml:"read_only_socket"`
}

// FilesystemPolicy controls filesystem restrictions inside the sandbox.
type FilesystemPolicy struct {
	WritableProjectDir bool     `json:"writable_project_dir" yaml:"writable_project_dir" toml:"writable_project_dir"`
	ExtraWritablePaths []string `json:"extra_writable_paths" yaml:"extra_writable_paths" toml:"extra_writable_paths"`
}

// Profile is a named preset of security policies.
type Profile struct {
	Name        string           `json:"name" yaml:"name" toml:"name"`
	Description string           `json:"description" yaml:"description" toml:"description"`
	Network     NetworkPolicy    `json:"network" yaml:"network" toml:"network"`
	Mount       MountPolicy      `json:"mount" yaml:"mount" toml:"mount"`
	Docker      DockerPolicy     `json:"docker" yaml:"docker" toml:"docker"`
	Filesystem  FilesystemPolicy `json:"filesystem" yaml:"filesystem" toml:"filesystem"`
}

// ProfileRegistry provides access to security profiles by name.
// This interface decouples consumers (CLI, sandbox orchestrator)
// from the concrete profile.Registry implementation.
type ProfileRegistry interface {
	Get(name string) (Profile, error)
	List() []string
}
