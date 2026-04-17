package lima

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/muneebs/airlock/internal/api"
)

// copyFileStreaming copies a regular file without loading it into memory.
// Lima disk images are multi-GB (often sparse); os.ReadFile would allocate
// a buffer of the apparent size and either OOM or thrash swap, appearing to
// the user as a hang during the snapshot phase.
func copyFileStreaming(src, dst string, perm fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, perm.Perm())
}

// safeFilePerm masks file permissions to strips SUID, SGID, and world-write bits,
// preventing privilege escalation via snapshot restore.
func safeFilePerm(m fs.FileMode) fs.FileMode {
	return m.Perm() & 0755
}

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
			return os.MkdirAll(targetPath, safeFilePerm(info.Mode()))
		}

		if !d.Type().IsRegular() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}

		return copyFileStreaming(path, targetPath, safeFilePerm(info.Mode()))
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
func (p *LimaProvider) HasCleanSnapshot(ctx context.Context, name string) (bool, error) {
	if err := validateName(name); err != nil {
		return false, fmt.Errorf("invalid vm name: %w", err)
	}
	cleanDir := filepath.Join(p.limaDir, name+"-clean")
	if _, err := os.Stat(cleanDir); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat clean snapshot dir: %w", err)
	}
	return true, nil
}

// ProvisionVM runs the standard provision commands for a fresh VM.
// This installs Node.js, pnpm, bun, Docker, and creates the airlock user.
func (p *LimaProvider) ProvisionVM(ctx context.Context, name string, nodeVersion int) error {
	for _, step := range p.ProvisionSteps(name, nodeVersion) {
		if err := step.Run(ctx); err != nil {
			return err
		}
	}
	return nil
}

// ProvisionSteps returns the provisioning sequence as discrete, named steps
// so callers can render per-step progress. Failing required steps propagate
// their error; non-fatal steps (Bun, Docker) swallow errors to match the
// previous ProvisionVM behavior.
func (p *LimaProvider) ProvisionSteps(name string, nodeVersion int) []api.ProvisionStep {
	if nodeVersion <= 0 {
		nodeVersion = 22
	}

	required := []struct {
		label string
		desc  string
		cmd   []string
	}{
		{"Installing system packages", "system packages", []string{"sudo", "bash", "-c", "export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install -y curl jq iptables unzip git"}},
		{fmt.Sprintf("Installing Node.js %d", nodeVersion), "node.js", []string{"sudo", "bash", "-c", fmt.Sprintf("curl -fsSL https://deb.nodesource.com/setup_%d.x | bash - && apt-get install -y nodejs", nodeVersion)}},
		{"Installing pnpm", "pnpm", []string{"sudo", "npm", "install", "-g", "pnpm"}},
		{"Creating airlock user", "create airlock user", []string{"sudo", "bash", "-c", "id airlock &>/dev/null || useradd -m -s /bin/bash airlock"}},
		// chown must be -xdev so it does not descend into virtiofs mounts
		// (e.g. /home/airlock/projects/<name>) where chown returns EPERM.
		{"Preparing airlock home", "setup airlock dirs", []string{"sudo", "bash", "-c", "mkdir -p /home/airlock/.npm-global /home/airlock/projects && find /home/airlock -xdev -exec chown airlock:airlock {} +"}},
		{"Configuring npm prefix", "npm prefix", []string{"sudo", "-u", "airlock", "bash", "--login", "-c", "npm config set prefix /home/airlock/.npm-global"}},
	}

	steps := make([]api.ProvisionStep, 0, len(required)+2)
	for _, r := range required {
		r := r
		steps = append(steps, api.ProvisionStep{
			Label: r.label,
			Run: func(ctx context.Context) error {
				if err := validateName(name); err != nil {
					return fmt.Errorf("invalid vm name: %w", err)
				}
				if _, err := p.Exec(ctx, name, r.cmd); err != nil {
					return fmt.Errorf("provision %s: %w", r.desc, err)
				}
				return nil
			},
		})
	}

	steps = append(steps,
		api.ProvisionStep{
			Label: "Installing Bun",
			Run: func(ctx context.Context) error {
				_ = p.installBun(ctx, name)
				return nil
			},
		},
		api.ProvisionStep{
			Label: "Installing Docker",
			Run: func(ctx context.Context) error {
				_ = p.installDocker(ctx, name)
				return nil
			},
		},
	)

	return steps
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
			return os.MkdirAll(targetPath, safeFilePerm(info.Mode()))
		}

		if !d.Type().IsRegular() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}

		return copyFileStreaming(path, targetPath, safeFilePerm(info.Mode()))
	})
}

// Verify LimaProvider implements api.Provider at compile time.
var _ api.Provider = (*LimaProvider)(nil)

// Verify LimaProvider implements api.Provisioner at compile time.
var _ api.Provisioner = (*LimaProvider)(nil)

// Verify LimaProvider implements api.ShellProvider at compile time.
var _ api.ShellProvider = (*LimaProvider)(nil)
