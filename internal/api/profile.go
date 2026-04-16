package api

import "github.com/muneebs/airlock/internal/profile"

// ProfileRegistry provides access to security profiles by name.
// This interface decouples consumers (CLI, sandbox orchestrator)
// from the concrete profile.Registry implementation.
type ProfileRegistry interface {
	Get(name string) (profile.Profile, error)
	List() []string
}
