package sandbox

import (
	"context"
	"fmt"

	"github.com/muneebs/airlock/internal/api"
)

// Stop gracefully stops a running sandbox.
func (m *Manager) Stop(ctx context.Context, name string) error {
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

	if !running {
		m.mu.Lock()
		info, _ = m.get(name)
		info.State = api.StateStopped
		if putErr := m.put(info); putErr != nil {
			m.mu.Unlock()
			return fmt.Errorf("save sandbox state: %w", putErr)
		}
		m.mu.Unlock()
		return nil
	}

	if err := m.provider.Stop(ctx, name); err != nil {
		m.mu.Lock()
		info, _ = m.get(name)
		info.State = api.StateErrored
		_ = m.put(info)
		m.mu.Unlock()
		return fmt.Errorf("stop VM: %w", err)
	}

	m.mu.Lock()
	info, _ = m.get(name)
	info.State = api.StateStopped
	if putErr := m.put(info); putErr != nil {
		m.mu.Unlock()
		return fmt.Errorf("save sandbox state: %w", putErr)
	}
	m.mu.Unlock()

	return nil
}
