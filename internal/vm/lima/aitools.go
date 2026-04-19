package lima

import (
	"context"
	"fmt"
)

// aiToolInstaller describes how to install one AI CLI tool inside a VM.
// New AI tools register themselves via registerAITool — the provisioning
// pipeline never switches on tool name, satisfying OCP.
type aiToolInstaller struct {
	Label     string
	RunsOnNpm bool
	Install   func(ctx context.Context, p *LimaProvider, name string) error
}

var aiToolRegistry = map[string]aiToolInstaller{}

func registerAITool(key string, t aiToolInstaller) {
	aiToolRegistry[key] = t
}

// lookupAITool returns the installer for a known tool, or (zero, false).
func lookupAITool(key string) (aiToolInstaller, bool) {
	t, ok := aiToolRegistry[key]
	return t, ok
}

// aiToolRequiresNpm reports whether an AI tool is installed via npm and
// therefore forces Node.js installation.
func aiToolRequiresNpm(tool string) bool {
	t, ok := lookupAITool(tool)
	return ok && t.RunsOnNpm
}

// npmInstallGlobal installs an npm package globally for the airlock user,
// using their login shell so npm's per-user prefix applies.
func npmInstallGlobal(ctx context.Context, p *LimaProvider, name, pkg string) error {
	// %q quotes pkg so a hostile registered name cannot break out of the
	// shell -c string. Today all callers pass static constants; defence in
	// depth for future additions.
	_, err := p.Exec(ctx, name, []string{
		"sudo", "-u", "airlock", "bash", "--login", "-c",
		fmt.Sprintf("npm install -g %q", pkg),
	})
	return err
}

func init() {
	registerAITool("claude-code", aiToolInstaller{
		Label:     "Installing Claude Code",
		RunsOnNpm: true,
		Install: func(ctx context.Context, p *LimaProvider, name string) error {
			return npmInstallGlobal(ctx, p, name, "@anthropic-ai/claude-code")
		},
	})
	registerAITool("gemini", aiToolInstaller{
		Label:     "Installing Gemini CLI",
		RunsOnNpm: true,
		Install: func(ctx context.Context, p *LimaProvider, name string) error {
			return npmInstallGlobal(ctx, p, name, "@google/gemini-cli")
		},
	})
	registerAITool("codex", aiToolInstaller{
		Label:     "Installing Codex CLI",
		RunsOnNpm: true,
		Install: func(ctx context.Context, p *LimaProvider, name string) error {
			return npmInstallGlobal(ctx, p, name, "@openai/codex")
		},
	})
	registerAITool("opencode", aiToolInstaller{
		Label: "Installing OpenCode",
		Install: func(ctx context.Context, p *LimaProvider, name string) error {
			// Installer writes to invoking user's home; run as airlock.
			_, err := p.Exec(ctx, name, []string{
				"sudo", "-u", "airlock", "bash", "--login", "-c",
				"curl -fsSL https://opencode.ai/install | bash",
			})
			return err
		},
	})
	registerAITool("ollama", aiToolInstaller{
		Label: "Installing Ollama",
		Install: func(ctx context.Context, p *LimaProvider, name string) error {
			// Accepted risk: curl | sh as root, matches vendor-documented
			// install (https://ollama.com/install.sh). Ollama publishes no
			// stable checksum or signed package for this path. The shell
			// runs inside the sandbox VM, not the host, so blast radius is
			// bounded to the VM the user opted to provision.
			_, err := p.Exec(ctx, name, []string{
				"sudo", "bash", "-c",
				"curl -fsSL https://ollama.com/install.sh | sh",
			})
			return err
		},
	})
}
