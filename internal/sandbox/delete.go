package sandbox

import (
	"context"
	"fmt"
)

// Destroy removes a sandbox entirely: stop the VM, delete it, and cleanup mounts.
func (m *Manager) Destroy(ctx context.Context, name string) error {
	m.mu.Lock()
	_, err := m.get(name)
	m.mu.Unlock()
	if err != nil {
		return err
	}

	running, err := m.provider.IsRunning(ctx, name)
	if err == nil && running {
		if stopErr := m.provider.Stop(ctx, name); stopErr != nil {
			return fmt.Errorf("stop VM before delete: %w", stopErr)
		}
	}

	exists, err := m.provider.Exists(ctx, name)
	if err != nil {
		return fmt.Errorf("check VM existence: %w", err)
	}

	if exists {
		if err := m.provider.Delete(ctx, name); err != nil {
			return fmt.Errorf("delete VM: %w", err)
		}
	}

	_ = m.mounts.Unregister(ctx, name, name)

	m.mu.Lock()
	_ = m.remove(name)
	m.mu.Unlock()

	return nil
}
