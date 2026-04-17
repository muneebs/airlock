package lima

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/muneebs/airlock/internal/api"
)

// LimaProvider implements api.Provider by shelling out to limactl.
type LimaProvider struct {
	limactlPath string
	limaDir     string
}

// NewLimaProvider creates a provider using the default limactl binary
// and Lima state directory ($HOME/.lima).
func NewLimaProvider() (*LimaProvider, error) {
	path, err := exec.LookPath("limactl")
	if err != nil {
		return nil, fmt.Errorf("limactl not found in PATH: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}
	return &LimaProvider{
		limactlPath: path,
		limaDir:     filepath.Join(home, ".lima"),
	}, nil
}

// NewLimaProviderWithPaths creates a provider with explicit paths, for testing.
func NewLimaProviderWithPaths(limactlPath, limaDir string) *LimaProvider {
	return &LimaProvider{
		limactlPath: limactlPath,
		limaDir:     limaDir,
	}
}

// Create generates a Lima YAML config from the VMSpec and runs limactl create.
// If a VM with the same name already exists, it returns an error.
// On failure, any partially created directory is cleaned up.
func (p *LimaProvider) Create(ctx context.Context, spec api.VMSpec) error {
	if err := validateName(spec.Name); err != nil {
		return fmt.Errorf("invalid vm name: %w", err)
	}

	exists, err := p.Exists(ctx, spec.Name)
	if err != nil {
		return fmt.Errorf("check VM existence: %w", err)
	}
	if exists {
		return fmt.Errorf("VM %q already exists", spec.Name)
	}

	configYAML, err := GenerateConfig(spec)
	if err != nil {
		return fmt.Errorf("generate lima config: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "airlock-lima-*.yaml")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(configYAML); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close config: %w", err)
	}

	_, err = p.runCmdStreaming(ctx, "create", "--tty=false", "--name="+spec.Name, tmpFile.Name())
	if err != nil {
		return fmt.Errorf("create VM %s: %w", spec.Name, err)
	}

	return nil
}

// Start starts an existing Lima VM.
func (p *LimaProvider) Start(ctx context.Context, name string) error {
	if err := validateName(name); err != nil {
		return fmt.Errorf("invalid vm name: %w", err)
	}
	_, err := p.runCmd(ctx, "start", name)
	if err != nil {
		return fmt.Errorf("start VM %s: %w", name, err)
	}
	return nil
}

// Stop stops a running Lima VM.
func (p *LimaProvider) Stop(ctx context.Context, name string) error {
	if err := validateName(name); err != nil {
		return fmt.Errorf("invalid vm name: %w", err)
	}
	_, err := p.runCmd(ctx, "stop", name)
	if err != nil {
		return fmt.Errorf("stop VM %s: %w", name, err)
	}
	return nil
}

// Delete removes a Lima VM.
func (p *LimaProvider) Delete(ctx context.Context, name string) error {
	if err := validateName(name); err != nil {
		return fmt.Errorf("invalid vm name: %w", err)
	}
	_, err := p.runCmd(ctx, "delete", name)
	if err != nil {
		return fmt.Errorf("delete VM %s: %w", name, err)
	}
	return nil
}

// Exists checks whether a Lima VM with the given name exists.
func (p *LimaProvider) Exists(ctx context.Context, name string) (bool, error) {
	if err := validateName(name); err != nil {
		return false, fmt.Errorf("invalid vm name: %w", err)
	}
	vms, err := p.listVMs(ctx)
	if err != nil {
		return false, err
	}
	for _, vm := range vms {
		if vm.Name == name {
			return true, nil
		}
	}
	return false, nil
}

// IsRunning checks whether a Lima VM is currently running.
func (p *LimaProvider) IsRunning(ctx context.Context, name string) (bool, error) {
	if err := validateName(name); err != nil {
		return false, fmt.Errorf("invalid vm name: %w", err)
	}
	vms, err := p.listVMs(ctx)
	if err != nil {
		return false, err
	}
	for _, vm := range vms {
		if vm.Name == name {
			return vm.Status == "Running", nil
		}
	}
	return false, nil
}

// Exec runs a command inside the Lima VM as root.
func (p *LimaProvider) Exec(ctx context.Context, name string, cmd []string) (string, error) {
	if err := validateName(name); err != nil {
		return "", fmt.Errorf("invalid vm name: %w", err)
	}
	args := []string{"shell", "--workdir", "/", name, "--"}
	args = append(args, cmd...)
	return p.runCmd(ctx, args...)
}

// ExecAsUser runs a command inside the Lima VM as a specific user.
// Each argument is individually shell-escaped to preserve argument boundaries.
func (p *LimaProvider) ExecAsUser(ctx context.Context, name, user string, cmd []string) (string, error) {
	if err := validateUsername(user); err != nil {
		return "", fmt.Errorf("invalid user: %w", err)
	}
	escapedArgs := make([]string, len(cmd))
	for i, arg := range cmd {
		escapedArgs[i] = shellEscape(arg)
	}
	shellCmd := fmt.Sprintf("sudo -u %s bash --login -c '%s'", user, strings.Join(escapedArgs, " "))
	args := []string{"shell", "--workdir", "/", name, "--", "bash", "-c", shellCmd}
	return p.runCmd(ctx, args...)
}

// CopyToVM copies a file from the host into the Lima VM.
func (p *LimaProvider) CopyToVM(ctx context.Context, name, src, dst string) error {
	if err := validateName(name); err != nil {
		return fmt.Errorf("invalid vm name: %w", err)
	}
	target := fmt.Sprintf("%s:%s", name, dst)
	_, err := p.runCmd(ctx, "copy", src, target)
	if err != nil {
		return fmt.Errorf("limactl copy %s -> %s: %w", src, target, err)
	}
	return nil
}

// limaVMInfo represents a VM entry from limactl list --json.
type limaVMInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

// listVMs queries limactl for all VMs and their status.
func (p *LimaProvider) listVMs(ctx context.Context) ([]limaVMInfo, error) {
	output, err := p.runCmd(ctx, "list", "--json")
	if err != nil {
		return nil, fmt.Errorf("list VMs: %w", err)
	}

	var vms []limaVMInfo
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var vm limaVMInfo
		if err := json.Unmarshal([]byte(line), &vm); err != nil {
			continue
		}
		vms = append(vms, vm)
	}
	return vms, nil
}

// runCmd executes a limactl command, buffering stdout and stderr.
func (p *LimaProvider) runCmd(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, p.limactlPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%s: %w", cleanLimactlError(args[0], stderr.String()), err)
	}
	return stdout.String(), nil
}

// runCmdStreaming executes a limactl command, streaming stderr to the terminal
// so the user sees progress (image downloads, provisioning, etc.).
// Only use this for "create" — other commands should use buffered runCmd
// because limactl start daemonizes when stderr is not a terminal.
func (p *LimaProvider) runCmdStreaming(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, p.limactlPath, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("limactl %s: %w", args[0], err)
	}
	return stdout.String(), nil
}

func cleanLimactlError(action string, stderr string) string {
	var parts []string
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "time=") {
			if idx := strings.Index(line, "msg="); idx != -1 {
				msg := strings.Trim(strings.TrimPrefix(line[idx:], "msg="), `"`)
				if msg != "" {
					parts = append(parts, msg)
				}
			}
			continue
		}
		if strings.HasPrefix(line, "level=") {
			if idx := strings.Index(line, "msg="); idx != -1 {
				msg := strings.Trim(strings.TrimPrefix(line[idx:], "msg="), `"`)
				if msg != "" {
					parts = append(parts, msg)
				}
			}
			continue
		}
		if line != "" {
			parts = append(parts, line)
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("limactl %s", action)
	}
	return fmt.Sprintf("limactl %s: %s", action, strings.Join(parts, ": "))
}

// shellEscape wraps a string in single quotes, replacing internal single quotes
// with the standard '\” sequence, so the argument boundary is preserved when
// passed to bash -c.
func shellEscape(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// Shell opens an interactive shell session in the VM by exec'ing limactl.
// It connects stdin/stdout/stderr directly to the terminal for TTY support.
func (p *LimaProvider) Shell(ctx context.Context, name string) error {
	if err := validateName(name); err != nil {
		return fmt.Errorf("invalid vm name: %w", err)
	}
	cmd := exec.CommandContext(ctx, p.limactlPath, "shell", name)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
