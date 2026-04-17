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

// ProgressFn receives human-readable stage names as a long-running operation
// moves through its internal phases (e.g. "generating config",
// "booting vm", "applying network policy"). Callers use it to surface live
// feedback in the UI without tapping into subprocess output streams.
type ProgressFn func(stage string)

// CreateOptions tunes the Create workflow.
type CreateOptions struct {
	// Progress receives stage updates as Create advances. May be nil.
	Progress ProgressFn
	// SkipNetworkPolicy defers iptables rule application. Callers must
	// invoke ApplyNetworkProfile themselves once the guest has iptables
	// installed (e.g. after provisioning). Setup uses this to avoid running
	// iptables-restore on a freshly booted Ubuntu image that may not yet
	// have the iptables backend initialized.
	SkipNetworkPolicy bool
}

// SandboxManager creates, inspects, and destroys isolated sandbox environments.
// Implementation must ensure each sandbox gets its own VM with no shared state.
type SandboxManager interface {
	Create(ctx context.Context, spec SandboxSpec) (SandboxInfo, error)
	// CreateWithProgress is Create with a callback that receives stage
	// names as the create workflow advances. Pass nil for progress to get
	// Create's behavior.
	CreateWithProgress(ctx context.Context, spec SandboxSpec, progress ProgressFn) (SandboxInfo, error)
	// CreateWithOptions is Create with a full options struct. Prefer this
	// when callers need to opt out of network policy application.
	CreateWithOptions(ctx context.Context, spec SandboxSpec, opts CreateOptions) (SandboxInfo, error)
	// ApplyNetworkProfile applies the stored profile's network policy to
	// an existing sandbox. Used after provisioning when Create was invoked
	// with SkipNetworkPolicy.
	ApplyNetworkProfile(ctx context.Context, name string) error
	Start(ctx context.Context, name string) error
	Run(ctx context.Context, name string, command []string) (string, error)
	Stop(ctx context.Context, name string) error
	Reset(ctx context.Context, name string) error
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
