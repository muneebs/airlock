package sandbox

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/muneebs/airlock/internal/api"
)

// agentCredentialEnv lists the host environment variables that hold AI-agent
// API credentials. They are forwarded into the VM ONLY for the "agent"
// profile — the profile whose entire purpose is to run an AI coding CLI. They
// are deliberately NOT forwarded for other profiles: injecting the user's API
// key into a sandbox that exists to run untrusted software would hand that
// software the key, defeating the isolation.
var agentCredentialEnv = []string{
	"ANTHROPIC_API_KEY",
	"ANTHROPIC_AUTH_TOKEN",
	"OPENAI_API_KEY",
	"GEMINI_API_KEY",
	"GOOGLE_API_KEY",
}

// forwardedAgentEnv returns "KEY=VALUE" assignments for each credential env var
// that is set on the host, suitable for prefixing a command with env(1). Empty
// when none are set.
func forwardedAgentEnv() []string {
	var out []string
	for _, key := range agentCredentialEnv {
		if v, ok := os.LookupEnv(key); ok && v != "" {
			out = append(out, key+"="+v)
		}
	}
	return out
}

// Run starts a sandbox (if not running), mounts the project, and executes
// the given command inside it. If spec.Command is set, that command is used;
// otherwise the detected runtime's run command is used.
func (m *Manager) Run(ctx context.Context, name string, command []string) (string, error) {
	m.mu.Lock()
	info, err := m.get(name)
	m.mu.Unlock()
	if err != nil {
		return "", err
	}
	profile := ""
	if info != nil {
		profile = info.Profile
	}

	running, err := m.provider.IsRunning(ctx, name)
	if err != nil {
		return "", fmt.Errorf("check VM status: %w", err)
	}

	if !running {
		if err := m.provider.Start(ctx, name); err != nil {
			return "", fmt.Errorf("start VM: %w", err)
		}
		m.mu.Lock()
		info, _ := m.get(name)
		if info != nil && info.State != api.StateRunning {
			info.State = api.StateRunning
			if putErr := m.put(info); putErr != nil {
				m.mu.Unlock()
				return "", fmt.Errorf("save sandbox state: %w", putErr)
			}
		}
		m.mu.Unlock()
	}

	if len(command) == 0 {
		return "", ErrInvalidSpec{Reason: "command is required"}
	}

	// For the agent profile, prefix the command with the forwarded credential
	// env so the AI CLI can authenticate without mounting the host home. env(1)
	// scopes the assignment to this one command; each token is shell-escaped by
	// ExecAsUser, so values are passed literally.
	if profile == "agent" {
		if creds := forwardedAgentEnv(); len(creds) > 0 {
			command = append(append([]string{"env"}, creds...), command...)
		}
	}

	output, err := m.provider.ExecAsUser(ctx, name, "airlock", command)
	if err != nil {
		return "", fmt.Errorf("exec command: %w", err)
	}

	return strings.TrimSpace(output), nil
}

// Start starts a stopped sandbox.
func (m *Manager) Start(ctx context.Context, name string) error {
	m.mu.Lock()
	_, err := m.get(name)
	m.mu.Unlock()
	if err != nil {
		return err
	}

	running, err := m.provider.IsRunning(ctx, name)
	if err != nil {
		return fmt.Errorf("check VM status: %w", err)
	}

	if running {
		return nil
	}

	if err := m.provider.Start(ctx, name); err != nil {
		return fmt.Errorf("start VM: %w", err)
	}

	m.mu.Lock()
	info, _ := m.get(name)
	if info != nil && info.State != api.StateRunning {
		info.State = api.StateRunning
		if putErr := m.put(info); putErr != nil {
			m.mu.Unlock()
			return fmt.Errorf("save sandbox state: %w", putErr)
		}
	}
	m.mu.Unlock()

	return nil
}
