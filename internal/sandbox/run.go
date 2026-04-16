package sandbox

import (
	"context"
	"fmt"
	"strings"

	"github.com/muneebs/airlock/internal/api"
)

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

	running, err := m.provider.IsRunning(ctx, name)
	if err != nil {
		return "", fmt.Errorf("check VM status: %w", err)
	}

	if !running {
		if err := m.provider.Start(ctx, name); err != nil {
			return "", fmt.Errorf("start VM: %w", err)
		}
		m.mu.Lock()
		info.State = api.StateRunning
		_ = m.put(info)
		m.mu.Unlock()
	}

	if len(command) == 0 {
		return "", ErrInvalidSpec{Reason: "command is required"}
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
	info, err := m.get(name)
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
	info.State = api.StateRunning
	_ = m.put(info)
	m.mu.Unlock()

	return nil
}
