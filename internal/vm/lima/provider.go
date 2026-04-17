package lima

import (
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

	_, err = p.runCmdDetached(ctx, "create", "--tty=false", "--name="+spec.Name, tmpFile.Name())
	if err != nil {
		return fmt.Errorf("create VM %s: %w", spec.Name, err)
	}

	return nil
}

// Start starts an existing Lima VM.
// First boot of a fresh VM can take several minutes (cloud-init, package
// installation, SSH setup). runCmdDetached is used because limactl start
// daemonizes qemu/vz; child processes inherit any pipe we assign to stderr,
// causing cmd.Wait to block until every descendant exits. Using real files
// avoids pipe inheritance so Wait returns as soon as limactl itself exits.
func (p *LimaProvider) Start(ctx context.Context, name string) error {
	if err := validateName(name); err != nil {
		return fmt.Errorf("invalid vm name: %w", err)
	}
	// --tty=false is required when the caller may not own a TTY (e.g. the
	// `airlock init` wizard handed its TTY to huh, or CI). Without it,
	// limactl renders progress via an interactive terminal writer that
	// corrupts or blocks on a non-tty stdout.
	_, err := p.runCmdDetached(ctx, "start", "--tty=false", name)
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
	_, err := p.runCmd(ctx, "stop", "--tty=false", name)
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
	_, err := p.runCmd(ctx, "delete", "--tty=false", name)
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

// Status returns Lima's lifecycle string for the VM, or "" if not found.
func (p *LimaProvider) Status(ctx context.Context, name string) (string, error) {
	if err := validateName(name); err != nil {
		return "", fmt.Errorf("invalid vm name: %w", err)
	}
	vms, err := p.listVMs(ctx)
	if err != nil {
		return "", err
	}
	for _, vm := range vms {
		if vm.Name == name {
			return vm.Status, nil
		}
	}
	return "", nil
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

// runCmd executes a limactl command using real files (not bytes.Buffer) for
// stdout and stderr. This matters because limactl invokes ssh with
// ControlMaster/ControlPersist, which leaves a background ssh process running
// after the shell command exits. Grandchildren inherit whatever fds we assign
// to the child. If those fds are pipes (as they are when cmd.Stdout/Stderr
// are io.Writers that are not *os.File), os/exec spawns a copier goroutine
// that blocks cmd.Wait until EOF — and EOF never arrives while the ssh master
// still holds the write end. Using real files (*os.File) skips the pipe
// entirely: Wait returns as soon as limactl itself exits, regardless of any
// persistent ssh masters or qemu/vz children still holding the fd.
func (p *LimaProvider) runCmd(ctx context.Context, args ...string) (string, error) {
	stdoutBytes, _, err := p.runCmdFiles(ctx, args...)
	return stdoutBytes, err
}

// runCmdDetached is a convenience wrapper for commands whose stdout is known
// to be progress noise rather than data (create, start). Stdout is discarded
// so we don't even allocate a tempfile for it.
func (p *LimaProvider) runCmdDetached(ctx context.Context, args ...string) (string, error) {
	_, _, err := p.runCmdFiles(ctx, args...)
	return "", err
}

// runCmdFiles is the shared implementation: tempfile for stdout, tempfile
// for stderr, both closed and read after the child exits.
func (p *LimaProvider) runCmdFiles(ctx context.Context, args ...string) (string, string, error) {
	stdoutFile, err := os.CreateTemp("", "airlock-lima-stdout-*")
	if err != nil {
		return "", "", fmt.Errorf("create stdout temp: %w", err)
	}
	defer os.Remove(stdoutFile.Name())
	defer stdoutFile.Close()

	stderrFile, err := os.CreateTemp("", "airlock-lima-stderr-*")
	if err != nil {
		return "", "", fmt.Errorf("create stderr temp: %w", err)
	}
	defer os.Remove(stderrFile.Name())
	defer stderrFile.Close()

	cmd := exec.CommandContext(ctx, p.limactlPath, args...)
	cmd.Stdout = stdoutFile
	cmd.Stderr = stderrFile

	runErr := cmd.Run()

	stdoutBytes, _ := os.ReadFile(stdoutFile.Name())
	stderrBytes, _ := os.ReadFile(stderrFile.Name())

	if runErr != nil {
		return string(stdoutBytes), string(stderrBytes), fmt.Errorf("%s: %w", cleanLimactlError(args[0], string(stderrBytes)), runErr)
	}
	return string(stdoutBytes), string(stderrBytes), nil
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
	// limactl shell logs in as the host user by default, which cannot access
	// /home/airlock/projects/<name>. Switch to the airlock user via sudo -iu
	// and cd into the project mount before handing off to an interactive bash.
	workdir := "/home/airlock/projects/" + name
	inner := fmt.Sprintf("cd %s && exec bash", shellEscape(workdir))
	cmd := exec.CommandContext(ctx, p.limactlPath, "shell", "--workdir", "/", name, "--", "sudo", "-iu", "airlock", "bash", "-c", inner)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
