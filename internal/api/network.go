package api

import "context"

// NetworkPolicy controls what outbound network access a sandbox has.
type NetworkPolicy struct {
	AllowDNS         bool `json:"allow_dns" yaml:"allow_dns" toml:"allow_dns"`
	AllowOutbound    bool `json:"allow_outbound" yaml:"allow_outbound" toml:"allow_outbound"`
	AllowEstablished bool `json:"allow_established" yaml:"allow_established" toml:"allow_established"`
	LockAfterSetup   bool `json:"lock_after_setup" yaml:"lock_after_setup" toml:"lock_after_setup"`

	// AllowlistHosts are hostnames that remain reachable on HTTPS (tcp/443)
	// even when outbound is otherwise blocked. This is what lets an AI coding
	// agent (claude, gemini, codex) reach its API from inside a locked
	// sandbox: the network stays closed to everything except these hosts.
	// Hostnames are resolved by iptables-restore inside the VM at apply time;
	// if a host's IPs rotate mid-session, re-applying the policy (airlock lock)
	// refreshes them. Entries must be valid DNS hostnames — anything else is
	// dropped when the ruleset is built (see allowlistHostRe).
	AllowlistHosts []string `json:"allowlist_hosts,omitempty" yaml:"allowlist_hosts,omitempty" toml:"allowlist_hosts,omitempty"`
}

// NetworkController manages iptables-based network isolation inside a sandbox.
type NetworkController interface {
	Lock(ctx context.Context, sandboxName string) error
	Unlock(ctx context.Context, sandboxName string) error
	ApplyPolicy(ctx context.Context, sandboxName string, policy NetworkPolicy) error
	RemovePolicy(ctx context.Context, sandboxName string) error
	IsLocked(ctx context.Context, sandboxName string) (bool, error)
}
