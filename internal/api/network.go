package api

import "context"

// NetworkPolicy controls what outbound network access a sandbox has.
type NetworkPolicy struct {
	AllowDNS         bool `json:"allow_dns" yaml:"allow_dns" toml:"allow_dns"`
	AllowOutbound    bool `json:"allow_outbound" yaml:"allow_outbound" toml:"allow_outbound"`
	AllowEstablished bool `json:"allow_established" yaml:"allow_established" toml:"allow_established"`
	LockAfterSetup   bool `json:"lock_after_setup" yaml:"lock_after_setup" toml:"lock_after_setup"`
}

// NetworkController manages iptables-based network isolation inside a sandbox.
type NetworkController interface {
	Lock(ctx context.Context, sandboxName string) error
	Unlock(ctx context.Context, sandboxName string) error
	ApplyPolicy(ctx context.Context, sandboxName string, policy NetworkPolicy) error
	IsLocked(ctx context.Context, sandboxName string) (bool, error)
}
