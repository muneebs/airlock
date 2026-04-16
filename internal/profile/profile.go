// Package profile defines security profiles that control sandbox isolation levels.
// Each profile is a named preset of network, mount, Docker, and filesystem policies.
// Profiles encode security expertise so users don't need to be experts.
package profile

import (
	"github.com/muneebs/airlock/internal/api"
)

// Profile is an alias for api.Profile, allowing this package to construct
// profiles using the shared abstraction defined in the api package.
type Profile = api.Profile

// Registry holds all available profiles. New profiles can be registered at init time.
type Registry struct {
	profiles map[string]api.Profile
}

// NewRegistry creates a profile registry with the four built-in profiles.
func NewRegistry() *Registry {
	r := &Registry{
		profiles: make(map[string]api.Profile),
	}
	for _, p := range builtins() {
		r.profiles[p.Name] = p
	}
	return r
}

// Get returns a profile by name. Returns an error if not found.
func (r *Registry) Get(name string) (api.Profile, error) {
	if p, ok := r.profiles[name]; ok {
		return p, nil
	}
	return api.Profile{}, ErrNotFound{Name: name}
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
func (r *Registry) Register(p api.Profile) error {
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
func builtins() []api.Profile {
	return []api.Profile{
		{
			Name:        "strict",
			Description: "No host mounts, network locked after install, no Docker. For completely untrusted software.",
			Network: api.NetworkPolicy{
				AllowDNS:         true,
				AllowOutbound:    false,
				AllowEstablished: false,
				LockAfterSetup:   true,
			},
			Mount: api.MountPolicy{
				Writable:        false,
				AllowHostMounts: false,
			},
			Docker: api.DockerPolicy{
				Allowed:        false,
				ReadOnlySocket: false,
			},
			Filesystem: api.FilesystemPolicy{
				WritableProjectDir: false,
			},
		},
		{
			Name:        "cautious",
			Description: "Read-only host mounts, network locked after install, restricted Docker. The default for running unknown software.",
			Network: api.NetworkPolicy{
				AllowDNS:         true,
				AllowOutbound:    false,
				AllowEstablished: true,
				LockAfterSetup:   true,
			},
			Mount: api.MountPolicy{
				Writable:        false,
				AllowHostMounts: true,
			},
			Docker: api.DockerPolicy{
				Allowed:        false,
				ReadOnlySocket: false,
			},
			Filesystem: api.FilesystemPolicy{
				WritableProjectDir: false,
				ExtraWritablePaths: []string{"/tmp"},
			},
		},
		{
			Name:        "dev",
			Description: "Read-write project mount, open network, Docker allowed. For developing on software you trust.",
			Network: api.NetworkPolicy{
				AllowDNS:         true,
				AllowOutbound:    true,
				AllowEstablished: true,
				LockAfterSetup:   false,
			},
			Mount: api.MountPolicy{
				Writable:        true,
				AllowHostMounts: true,
			},
			Docker: api.DockerPolicy{
				Allowed:        true,
				ReadOnlySocket: false,
			},
			Filesystem: api.FilesystemPolicy{
				WritableProjectDir: true,
			},
		},
		{
			Name:        "trusted",
			Description: "Full access. Only for software you author or fully trust.",
			Network: api.NetworkPolicy{
				AllowDNS:         true,
				AllowOutbound:    true,
				AllowEstablished: true,
				LockAfterSetup:   false,
			},
			Mount: api.MountPolicy{
				Writable:        true,
				AllowHostMounts: true,
			},
			Docker: api.DockerPolicy{
				Allowed:        true,
				ReadOnlySocket: false,
			},
			Filesystem: api.FilesystemPolicy{
				WritableProjectDir: true,
			},
		},
	}
}
