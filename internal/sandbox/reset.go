package sandbox

import (
	"context"
	"fmt"

	"github.com/muneebs/airlock/internal/api"
)

// Reset restores a sandbox to its clean snapshot state. The VM must exist
// and should be stopped first. If no clean snapshot exists, Reset returns
// an error.
func (m *Manager) Reset(ctx context.Context, name string) error {
	m.mu.Lock()
	info, err := m.get(name)
	m.mu.Unlock()
	if err != nil {
		return err
	}

	if !m.resetter.HasCleanSnapshot(name) {
		return fmt.Errorf("no clean snapshot found for sandbox %q", name)
	}

	running, err := m.provider.IsRunning(ctx, name)
	if err != nil {
		return fmt.Errorf("check VM status: %w", err)
	}

	if running {
		if err := m.provider.Stop(ctx, name); err != nil {
			return fmt.Errorf("stop VM before reset: %w", err)
		}
		m.mu.Lock()
		info.State = api.StateStopped
		_ = m.put(info)
		m.mu.Unlock()
	}

	if err := m.resetter.RestoreClean(ctx, name); err != nil {
		m.mu.Lock()
		info.State = api.StateErrored
		_ = m.put(info)
		m.mu.Unlock()
		return fmt.Errorf("restore clean snapshot: %w", err)
	}

	if err := m.provider.Start(ctx, name); err != nil {
		m.mu.Lock()
		info.State = api.StateErrored
		_ = m.put(info)
		m.mu.Unlock()
		return fmt.Errorf("start VM after reset: %w", err)
	}

	m.mu.Lock()
	info.State = api.StateRunning
	_ = m.put(info)
	m.mu.Unlock()

	return nil
}
