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
func (p *LimaProvider) Create(ctx context.Context, spec api.VMSpec) error {
	if err := validateName(spec.Name); err != nil {
		return fmt.Errorf("invalid vm name: %w", err)
	}
	configYAML, err := GenerateConfig(spec)
	if err != nil {
		return fmt.Errorf("generate lima config: %w", err)
	}

	dir := filepath.Join(p.limaDir, spec.Name)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create vm dir: %w", err)
	}

	configPath := filepath.Join(dir, "lima.yaml")
	if err := os.WriteFile(configPath, []byte(configYAML), 0600); err != nil {
		return fmt.Errorf("write lima.yaml: %w", err)
	}

	_, err = p.runCmd(ctx, "create", "--name="+spec.Name, configPath)
	if err != nil {
		return fmt.Errorf("limactl create %s: %w", spec.Name, err)
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
		return fmt.Errorf("limactl start %s: %w", name, err)
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
		return fmt.Errorf("limactl stop %s: %w", name, err)
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
		return fmt.Errorf("limactl delete %s: %w", name, err)
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
		return nil, fmt.Errorf("limactl list: %w", err)
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

// runCmd executes a limactl command with the given arguments.
func (p *LimaProvider) runCmd(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, p.limactlPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%s %s: %w\n%s",
			p.limactlPath, strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String(), nil
}

// shellEscape wraps a string in single quotes, escaping internal single quotes.
func shellEscape(s string) string {
	return strings.ReplaceAll(s, "'", "'\\''")
}
