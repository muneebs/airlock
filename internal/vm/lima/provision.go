package lima

import (
	"context"
	"fmt"

	"github.com/muneebs/airlock/internal/api"
)

// ProvisionVM runs the provision sequence for a fresh VM.
// Exact steps depend on opts; the baseline always installs system packages
// and creates the airlock user.
func (p *LimaProvider) ProvisionVM(ctx context.Context, name string, opts api.ProvisionOptions) error {
	for _, step := range p.ProvisionSteps(name, opts) {
		if err := step.Run(ctx); err != nil {
			return err
		}
	}
	return nil
}

// sudoersNopasswdScript validates the sudoers drop-in with visudo before
// installing it, so a malformed policy cannot lock root out of the VM.
const sudoersNopasswdScript = `set -e
tmp=$(mktemp)
printf 'airlock ALL=(ALL) NOPASSWD:ALL\n' > "$tmp"
chmod 0440 "$tmp"
visudo -cf "$tmp"
mv "$tmp" /etc/sudoers.d/airlock`

// ProvisionSteps returns the provisioning sequence as discrete, named steps
// so callers can render per-step progress. The baseline (system packages,
// airlock user, airlock home) always runs. Node.js/Bun/Docker and AI tools
// install only when opts requests them. Failing baseline steps propagate
// their error; optional runtime and AI tool installs swallow errors so a
// broken install script cannot brick the VM.
func (p *LimaProvider) ProvisionSteps(name string, opts api.ProvisionOptions) []api.ProvisionStep {
	nodeVersion := opts.NodeVersion
	if nodeVersion <= 0 {
		nodeVersion = 22
	}

	needNode := opts.InstallNode
	for _, t := range opts.AITools {
		if aiToolRequiresNpm(t) {
			needNode = true
			break
		}
	}

	type shellStep struct {
		label string
		desc  string
		cmd   []string
	}

	baseline := []shellStep{
		{"Installing system packages", "system packages", []string{"sudo", "bash", "-c", "export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install -y curl jq iptables unzip git"}},
		{"Creating airlock user", "create airlock user", []string{"sudo", "bash", "-c", "id airlock &>/dev/null || useradd -m -s /bin/bash airlock"}},
		{"Granting passwordless sudo", "sudoers nopasswd", []string{"sudo", "bash", "-c", sudoersNopasswdScript}},
		// chown must be -xdev so it does not descend into virtiofs mounts
		// (e.g. /home/airlock/projects/<name>) where chown returns EPERM.
		// -xdev alone still visits the mountpoint entry itself, so prune
		// /home/airlock/projects explicitly and chown only that directory
		// (not its contents).
		{"Preparing airlock home", "setup airlock dirs", []string{"sudo", "bash", "-c", "mkdir -p /home/airlock/.npm-global /home/airlock/projects && find /home/airlock -xdev -path /home/airlock/projects -prune -o -print0 | xargs -0 chown airlock:airlock && chown airlock:airlock /home/airlock/projects"}},
	}

	var node []shellStep
	if needNode {
		node = []shellStep{
			{fmt.Sprintf("Installing Node.js %d", nodeVersion), "node.js", []string{"sudo", "bash", "-c", fmt.Sprintf("curl -fsSL https://deb.nodesource.com/setup_%d.x | bash - && apt-get install -y nodejs", nodeVersion)}},
			{"Installing pnpm", "pnpm", []string{"sudo", "npm", "install", "-g", "pnpm"}},
			{"Configuring npm prefix", "npm prefix", []string{"sudo", "-u", "airlock", "bash", "--login", "-c", "npm config set prefix /home/airlock/.npm-global"}},
		}
	}

	steps := make([]api.ProvisionStep, 0, len(baseline)+len(node)+len(opts.AITools)+2)
	appendRequired := func(s shellStep) {
		steps = append(steps, api.ProvisionStep{
			Label: s.label,
			Run: func(ctx context.Context) error {
				if err := validateName(name); err != nil {
					return fmt.Errorf("invalid vm name: %w", err)
				}
				if _, err := p.Exec(ctx, name, s.cmd); err != nil {
					return fmt.Errorf("provision %s: %w", s.desc, err)
				}
				return nil
			},
		})
	}
	for _, s := range baseline {
		appendRequired(s)
	}
	for _, s := range node {
		appendRequired(s)
	}

	if opts.InstallBun {
		steps = append(steps, api.ProvisionStep{
			Label: "Installing Bun",
			Run: func(ctx context.Context) error {
				_ = p.installBun(ctx, name)
				return nil
			},
		})
	}
	if opts.InstallDocker {
		steps = append(steps, api.ProvisionStep{
			Label: "Installing Docker",
			Run: func(ctx context.Context) error {
				_ = p.installDocker(ctx, name)
				return nil
			},
		})
	}

	for _, t := range opts.AITools {
		tool, ok := lookupAITool(t)
		if !ok {
			continue
		}
		install := tool.Install
		steps = append(steps, api.ProvisionStep{
			Label: tool.Label,
			Run: func(ctx context.Context) error {
				_ = install(ctx, p, name)
				return nil
			},
		})
	}

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
