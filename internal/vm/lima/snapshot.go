package lima

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/muneebs/airlock/internal/api"
)

// SnapshotClean copies the VM's Lima directory to a -clean baseline,
// excluding runtime files like sockets. This allows airlock reset to
// restore the VM to a clean state without re-provisioning.
func (p *LimaProvider) SnapshotClean(ctx context.Context, name string) error {
	if err := validateName(name); err != nil {
		return fmt.Errorf("invalid vm name: %w", err)
	}
	vmDir := filepath.Join(p.limaDir, name)
	cleanDir := filepath.Join(p.limaDir, name+"-clean")

	if _, err := os.Stat(vmDir); err != nil {
		return fmt.Errorf("vm dir %s not found: %w", vmDir, err)
	}

	if err := os.RemoveAll(cleanDir); err != nil {
		return fmt.Errorf("remove old clean dir: %w", err)
	}

	return filepath.WalkDir(vmDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(vmDir, path)
		if err != nil {
			return err
		}

		// Skip sockets and other runtime files
		if strings.HasSuffix(relPath, ".sock") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		targetPath := filepath.Join(cleanDir, relPath)

		if d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			return os.MkdirAll(targetPath, info.Mode())
		}

		if !d.Type().IsRegular() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.WriteFile(targetPath, data, info.Mode()); err != nil {
			return err
		}
		return os.Chmod(targetPath, info.Mode().Perm())
	})
}

// RestoreClean copies the -clean baseline back over the VM directory,
// restoring it to a freshly-provisioned state. The VM must be stopped.
func (p *LimaProvider) RestoreClean(ctx context.Context, name string) error {
	if err := validateName(name); err != nil {
		return fmt.Errorf("invalid vm name: %w", err)
	}
	cleanDir := filepath.Join(p.limaDir, name+"-clean")
	vmDir := filepath.Join(p.limaDir, name)

	if _, err := os.Stat(cleanDir); err != nil {
		return fmt.Errorf("clean baseline %s not found: %w", cleanDir, err)
	}

	if err := os.RemoveAll(vmDir); err != nil {
		return fmt.Errorf("remove vm dir: %w", err)
	}

	return copyDir(cleanDir, vmDir)
}

// HasCleanSnapshot checks whether a -clean baseline exists for the VM.
func (p *LimaProvider) HasCleanSnapshot(name string) bool {
	if err := validateName(name); err != nil {
		return false
	}
	cleanDir := filepath.Join(p.limaDir, name+"-clean")
	_, err := os.Stat(cleanDir)
	return err == nil
}

// ProvisionVM runs the standard provision commands for a fresh VM.
// This installs Node.js, pnpm, bun, Docker, and creates the airlock user.
func (p *LimaProvider) ProvisionVM(ctx context.Context, name string, nodeVersion int) error {
	if err := validateName(name); err != nil {
		return fmt.Errorf("invalid vm name: %w", err)
	}
	if nodeVersion <= 0 {
		nodeVersion = 22
	}

	provisionCmds := []struct {
		desc string
		cmd  []string
	}{
		{"system packages", []string{"sudo", "bash", "-c", "export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install -y curl jq iptables unzip git"}},
		{"node.js", []string{"sudo", "bash", "-c", fmt.Sprintf("curl -fsSL https://deb.nodesource.com/setup_%d.x | bash - && apt-get install -y nodejs", nodeVersion)}},
		{"pnpm", []string{"sudo", "npm", "install", "-g", "pnpm"}},
		{"create airlock user", []string{"sudo", "bash", "-c", "id airlock &>/dev/null || useradd -m -s /bin/bash airlock"}},
		{"setup airlock dirs", []string{"sudo", "bash", "-c", "mkdir -p /home/airlock/.npm-global /home/airlock/projects && chown -R airlock:airlock /home/airlock"}},
		{"npm prefix", []string{"sudo", "-u", "airlock", "bash", "--login", "-c", "npm config set prefix /home/airlock/.npm-global"}},
	}

	for _, pc := range provisionCmds {
		_, err := p.Exec(ctx, name, pc.cmd)
		if err != nil {
			return fmt.Errorf("provision %s: %w", pc.desc, err)
		}
	}

	// Non-fatal provisions
	_ = p.installBun(ctx, name)
	_ = p.installDocker(ctx, name)

	return nil
}

func (p *LimaProvider) installBun(ctx context.Context, name string) error {
	_, err := p.Exec(ctx, name, []string{
		"sudo", "bash", "-c",
		"export HOME=/root && curl -fsSL https://bun.sh/install | bash && cp /root/.bun/bin/bun /usr/local/bin/bun && chmod +x /usr/local/bin/bun",
	})
	return err
}

func (p *LimaProvider) installDocker(ctx context.Context, name string) error {
	if _, err := p.Exec(ctx, name, []string{"sudo", "bash", "-c", "curl -fsSL https://get.docker.com | bash"}); err != nil {
		return err
	}
	_, err := p.Exec(ctx, name, []string{"sudo", "usermod", "-aG", "docker", "airlock"})
	return err
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if strings.HasSuffix(relPath, ".sock") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		targetPath := filepath.Join(dst, relPath)

		if d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return err
			}
			return os.MkdirAll(targetPath, info.Mode())
		}

		if !d.Type().IsRegular() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.WriteFile(targetPath, data, info.Mode()); err != nil {
			return err
		}
		return os.Chmod(targetPath, info.Mode().Perm())
	})
}

// Verify LimaProvider implements api.Provider at compile time.
var _ api.Provider = (*LimaProvider)(nil)
