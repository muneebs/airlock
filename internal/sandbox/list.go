package sandbox

import (
	"context"

	"github.com/muneebs/airlock/internal/api"
)

// List returns all sandboxes with their current status. It queries the VM provider
// to determine actual running state, updating stored sandbox info if it differs.
func (m *Manager) List(ctx context.Context) ([]api.SandboxInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]api.SandboxInfo, 0, len(m.sandboxes))
	for _, info := range m.sandboxes {
		running, err := m.provider.IsRunning(ctx, info.Name)
		if err != nil {
			result = append(result, *info)
			continue
		}

		if info.State == api.StateErrored {
			result = append(result, *info)
			continue
		}

		if running && info.State != api.StateRunning {
			info.State = api.StateRunning
			_ = m.put(info)
		} else if !running && info.State == api.StateRunning {
			info.State = api.StateStopped
			_ = m.put(info)
		}

		result = append(result, *info)
	}

	return result, nil
}

// Status returns the current status of a single sandbox.
func (m *Manager) Status(ctx context.Context, name string) (api.SandboxInfo, error) {
	m.mu.Lock()
	info, err := m.get(name)
	m.mu.Unlock()
	if err != nil {
		return api.SandboxInfo{}, err
	}

	if info.State == api.StateErrored {
		return *info, nil
	}

	running, err := m.provider.IsRunning(ctx, name)
	if err != nil {
		return *info, nil
	}

	if running && info.State != api.StateRunning {
		info.State = api.StateRunning
		m.mu.Lock()
		_ = m.put(info)
		m.mu.Unlock()
	} else if !running && info.State == api.StateRunning {
		info.State = api.StateStopped
		m.mu.Lock()
		_ = m.put(info)
		m.mu.Unlock()
	}

	return *info, nil
}
