package profile

import (
	"testing"

	"github.com/muneebs/airlock/internal/api"
)

func TestNewRegistryHasAllBuiltins(t *testing.T) {
	r := NewRegistry()
	expected := []string{"strict", "cautious", "dev", "trusted"}
	for _, name := range expected {
		p, err := r.Get(name)
		if err != nil {
			t.Errorf("expected profile %q to exist, got error: %v", name, err)
			continue
		}
		if p.Name != name {
			t.Errorf("expected name %q, got %q", name, p.Name)
		}
		if p.Description == "" {
			t.Errorf("profile %q has no description", name)
		}
	}
}

func TestGetNotFound(t *testing.T) {
	r := NewRegistry()
	_, err := r.Get("nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent profile")
	}
	if _, ok := err.(ErrNotFound); !ok {
		t.Errorf("expected ErrNotFound, got %T: %v", err, err)
	}
}

func TestRegisterCustomProfile(t *testing.T) {
	r := NewRegistry()
	custom := Profile{
		Name:        "custom-test",
		Description: "A test profile",
		Network: api.NetworkPolicy{
			AllowDNS:      true,
			AllowOutbound: true,
		},
		Mount: api.MountPolicy{
			Writable: true,
		},
	}

	err := r.Register(custom)
	if err != nil {
		t.Fatalf("Register() error: %v", err)
	}

	got, err := r.Get("custom-test")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if got.Name != "custom-test" {
		t.Errorf("expected name custom-test, got %s", got.Name)
	}
}

func TestRegisterDuplicateFails(t *testing.T) {
	r := NewRegistry()
	err := r.Register(Profile{Name: "strict"})
	if err == nil {
		t.Error("expected error when registering duplicate profile")
	}
	if _, ok := err.(ErrAlreadyExists); !ok {
		t.Errorf("expected ErrAlreadyExists, got %T: %v", err, err)
	}
}

func TestListProfiles(t *testing.T) {
	r := NewRegistry()
	names := r.List()
	if len(names) < 4 {
		t.Errorf("expected at least 4 profiles, got %d", len(names))
	}
}

func TestStrictProfilePolicies(t *testing.T) {
	r := NewRegistry()
	p, _ := r.Get("strict")

	if p.Network.AllowOutbound {
		t.Error("strict profile should not allow outbound")
	}
	if p.Network.LockAfterSetup != true {
		t.Error("strict profile should lock network after setup")
	}
	if p.Mount.AllowHostMounts {
		t.Error("strict profile should not allow host mounts")
	}
	if p.Docker.Allowed {
		t.Error("strict profile should not allow Docker")
	}
	if p.Filesystem.WritableProjectDir {
		t.Error("strict profile should not allow writable project dir")
	}
}

func TestCautiousProfilePolicies(t *testing.T) {
	r := NewRegistry()
	p, _ := r.Get("cautious")

	if p.Network.AllowOutbound {
		t.Error("cautious profile should not allow outbound")
	}
	if !p.Network.AllowEstablished {
		t.Error("cautious profile should allow established connections")
	}
	if !p.Mount.AllowHostMounts {
		t.Error("cautious profile should allow host mounts")
	}
	if p.Mount.Writable {
		t.Error("cautious profile mounts should be read-only")
	}
	if p.Docker.Allowed {
		t.Error("cautious profile should not allow Docker by default")
	}
}

func TestDevProfilePolicies(t *testing.T) {
	r := NewRegistry()
	p, _ := r.Get("dev")

	if !p.Network.AllowOutbound {
		t.Error("dev profile should allow outbound")
	}
	if p.Network.LockAfterSetup {
		t.Error("dev profile should not lock network after setup")
	}
	if !p.Mount.Writable {
		t.Error("dev profile should allow writable mounts")
	}
	if !p.Docker.Allowed {
		t.Error("dev profile should allow Docker")
	}
	if !p.Filesystem.WritableProjectDir {
		t.Error("dev profile should allow writable project dir")
	}
}

func TestTrustedProfilePolicies(t *testing.T) {
	r := NewRegistry()
	p, _ := r.Get("trusted")

	if !p.Network.AllowOutbound {
		t.Error("trusted profile should allow outbound")
	}
	if !p.Mount.Writable {
		t.Error("trusted profile should allow writable mounts")
	}
	if !p.Docker.Allowed {
		t.Error("trusted profile should allow Docker")
	}
	if !p.Filesystem.WritableProjectDir {
		t.Error("trusted profile should allow writable project dir")
	}
}
