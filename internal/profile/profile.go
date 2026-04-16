// Package profile defines security profiles that control sandbox isolation levels.
// Each profile is a named preset of network, mount, Docker, and filesystem policies.
// Profiles encode security expertise so users don't need to be experts.
package profile

// NetworkPolicy controls outbound network access within a sandbox.
type NetworkPolicy struct {
	AllowDNS         bool `json:"allow_dns" yaml:"allow_dns" toml:"allow_dns"`
	AllowOutbound    bool `json:"allow_outbound" yaml:"allow_outbound" toml:"allow_outbound"`
	AllowEstablished bool `json:"allow_established" yaml:"allow_established" toml:"allow_established"`
	LockAfterSetup   bool `json:"lock_after_setup" yaml:"lock_after_setup" toml:"lock_after_setup"`
}

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

// Registry holds all available profiles. New profiles can be registered at init time.
type Registry struct {
	profiles map[string]Profile
}

// NewRegistry creates a profile registry with the four built-in profiles.
func NewRegistry() *Registry {
	r := &Registry{
		profiles: make(map[string]Profile),
	}
	for _, p := range builtins() {
		r.profiles[p.Name] = p
	}
	return r
}

// Get returns a profile by name. Returns an error if not found.
func (r *Registry) Get(name string) (Profile, error) {
	if p, ok := r.profiles[name]; ok {
		return p, nil
	}
	return Profile{}, ErrNotFound{Name: name}
}

// List returns all registered profile names.
func (r *Registry) List() []string {
	names := make([]string, 0, len(r.profiles))
	for name := range r.profiles {
		names = append(names, name)
	}
	return names
}

// Register adds a custom profile to the registry.
func (r *Registry) Register(p Profile) error {
	if _, exists := r.profiles[p.Name]; exists {
		return ErrAlreadyExists{Name: p.Name}
	}
	r.profiles[p.Name] = p
	return nil
}

// ErrNotFound is returned when a profile name is not in the registry.
type ErrNotFound struct {
	Name string
}

func (e ErrNotFound) Error() string {
	return "profile not found: " + e.Name
}

// ErrAlreadyExists is returned when registering a profile that already exists.
type ErrAlreadyExists struct {
	Name string
}

func (e ErrAlreadyExists) Error() string {
	return "profile already exists: " + e.Name
}

// builtins returns the four standard security profiles.
func builtins() []Profile {
	return []Profile{
		{
			Name:        "strict",
			Description: "No host mounts, network locked after install, no Docker. For completely untrusted software.",
			Network: NetworkPolicy{
				AllowDNS:         true,
				AllowOutbound:    false,
				AllowEstablished: false,
				LockAfterSetup:   true,
			},
			Mount: MountPolicy{
				Writable:        false,
				AllowHostMounts: false,
			},
			Docker: DockerPolicy{
				Allowed:        false,
				ReadOnlySocket: false,
			},
			Filesystem: FilesystemPolicy{
				WritableProjectDir: false,
			},
		},
		{
			Name:        "cautious",
			Description: "Read-only host mounts, network locked after install, restricted Docker. The default for running unknown software.",
			Network: NetworkPolicy{
				AllowDNS:         true,
				AllowOutbound:    false,
				AllowEstablished: true,
				LockAfterSetup:   true,
			},
			Mount: MountPolicy{
				Writable:        false,
				AllowHostMounts: true,
			},
			Docker: DockerPolicy{
				Allowed:        false,
				ReadOnlySocket: false,
			},
			Filesystem: FilesystemPolicy{
				WritableProjectDir: false,
				ExtraWritablePaths: []string{"/tmp"},
			},
		},
		{
			Name:        "dev",
			Description: "Read-write project mount, open network, Docker allowed. For developing on software you trust.",
			Network: NetworkPolicy{
				AllowDNS:         true,
				AllowOutbound:    true,
				AllowEstablished: true,
				LockAfterSetup:   false,
			},
			Mount: MountPolicy{
				Writable:        true,
				AllowHostMounts: true,
			},
			Docker: DockerPolicy{
				Allowed:        true,
				ReadOnlySocket: false,
			},
			Filesystem: FilesystemPolicy{
				WritableProjectDir: true,
			},
		},
		{
			Name:        "trusted",
			Description: "Full access. Only for software you author or fully trust.",
			Network: NetworkPolicy{
				AllowDNS:         true,
				AllowOutbound:    true,
				AllowEstablished: true,
				LockAfterSetup:   false,
			},
			Mount: MountPolicy{
				Writable:        true,
				AllowHostMounts: true,
			},
			Docker: DockerPolicy{
				Allowed:        true,
				ReadOnlySocket: false,
			},
			Filesystem: FilesystemPolicy{
				WritableProjectDir: true,
			},
		},
	}
}
