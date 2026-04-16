// Package api defines the core interfaces that decouple high-level orchestration
// from low-level implementations. Every consumer depends on these interfaces;
// every provider implements them.
package api

import (
	"context"
	"time"
)

// SandboxState represents the lifecycle state of a sandbox.
type SandboxState string

const (
	StateCreating SandboxState = "creating"
	StateRunning  SandboxState = "running"
	StateStopped  SandboxState = "stopped"
	StateErrored  SandboxState = "errored"
)

// SandboxInfo holds metadata about a sandbox instance.
type SandboxInfo struct {
	Name      string       `json:"name" yaml:"name"`
	State     SandboxState `json:"state" yaml:"state"`
	Profile   string       `json:"profile" yaml:"profile"`
	Runtime   string       `json:"runtime" yaml:"runtime"`
	Source    string       `json:"source" yaml:"source"`
	CreatedAt time.Time    `json:"created_at" yaml:"created_at"`
	Ephemeral bool         `json:"ephemeral" yaml:"ephemeral"`
	CPU       int          `json:"cpu" yaml:"cpu"`
	Memory    string       `json:"memory" yaml:"memory"`
	Disk      string       `json:"disk" yaml:"disk"`
}

// SandboxManager creates, inspects, and destroys isolated sandbox environments.
// Implementation must ensure each sandbox gets its own VM with no shared state.
type SandboxManager interface {
	Create(ctx context.Context, spec SandboxSpec) (SandboxInfo, error)
	Start(ctx context.Context, name string) error
	Stop(ctx context.Context, name string) error
	Destroy(ctx context.Context, name string) error
	Status(ctx context.Context, name string) (SandboxInfo, error)
	List(ctx context.Context) ([]SandboxInfo, error)
}

// SandboxSpec defines what to create.
type SandboxSpec struct {
	Name      string `json:"name" yaml:"name"`
	Source    string `json:"source" yaml:"source"`
	Runtime   string `json:"runtime" yaml:"runtime"`
	Profile   string `json:"profile" yaml:"profile"`
	Ephemeral bool   `json:"ephemeral" yaml:"ephemeral"`
	Docker    bool   `json:"docker" yaml:"docker"`

	// Resources override profile defaults when set.
	CPU    *int   `json:"cpu,omitempty" yaml:"cpu,omitempty"`
	Memory string `json:"memory,omitempty" yaml:"memory,omitempty"`
	Disk   string `json:"disk,omitempty" yaml:"disk,omitempty"`

	// Ports is a port range string like "3000:9999".
	Ports string `json:"ports,omitempty" yaml:"ports,omitempty"`

	// Command runs immediately after sandbox creation.
	Command string `json:"command,omitempty" yaml:"command,omitempty"`
}
