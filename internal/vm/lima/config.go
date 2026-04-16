// Package lima implements the vm.Provider interface using Lima
// (https://github.com/lima-vm/lima) on macOS. It shells out to limactl
// for all VM lifecycle operations and generates Lima YAML configs from
// the api.VMSpec domain type.
package lima

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/muneebs/airlock/internal/api"
	"gopkg.in/yaml.v3"
	"strconv"
)

// LimaConfig represents the Lima YAML configuration file format.
type LimaConfig struct {
	VMType       string            `yaml:"vmType"`
	OS           string            `yaml:"os"`
	Arch         string            `yaml:"arch"`
	CPUs         int               `yaml:"cpus"`
	Memory       string            `yaml:"memory"`
	Disk         string            `yaml:"disk"`
	MountType    string            `yaml:"mountType"`
	Images       []LimaImage       `yaml:"images"`
	Mounts       []LimaMount       `yaml:"mounts"`
	PortForwards []LimaPortForward `yaml:"portForwards,omitempty"`
	Provision    []LimaProvision   `yaml:"provision,omitempty"`
}

type LimaImage struct {
	Location string `yaml:"location"`
	Arch     string `yaml:"arch"`
}

type LimaMount struct {
	Location     string `yaml:"location"`
	MountPoint   string `yaml:"mountPoint,omitempty"`
	Writable     bool   `yaml:"writable"`
	MountInotify bool   `yaml:"mountInotify,omitempty"`
}

type LimaPortForward struct {
	GuestPortRange [2]int `yaml:"guestPortRange"`
	HostPortRange  [2]int `yaml:"hostPortRange"`
}

type LimaProvision struct {
	Mode   string `yaml:"mode"`
	Script string `yaml:"script"`
}

// GenerateConfig produces a Lima YAML config from a VMSpec.
// It translates domain-level requirements (cpu, memory, disk, mounts, ports)
// into the Lima-specific YAML format.
func GenerateConfig(spec api.VMSpec) (string, error) {
	if err := validateSpec(spec); err != nil {
		return "", fmt.Errorf("invalid vm spec: %w", err)
	}

	cfg := LimaConfig{
		VMType:    "vz",
		OS:        "Linux",
		Arch:      "default",
		CPUs:      spec.CPU,
		Memory:    spec.Memory,
		Disk:      spec.Disk,
		MountType: "virtiofs",
		Images: []LimaImage{
			{Location: "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-arm64.img", Arch: "aarch64"},
			{Location: "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img", Arch: "x86_64"},
		},
	}

	for _, m := range spec.Mounts {
		lm := LimaMount{
			Location:   m.HostPath,
			MountPoint: m.GuestPath,
			Writable:   m.Writable,
		}
		if m.Inotify {
			lm.MountInotify = true
		}
		cfg.Mounts = append(cfg.Mounts, lm)
	}

	if spec.Ports != "" {
		pf, err := parsePortRange(spec.Ports)
		if err != nil {
			return "", fmt.Errorf("parse port range: %w", err)
		}
		cfg.PortForwards = []LimaPortForward{pf}
	}

	if len(spec.ProvisionCmds) > 0 {
		script := strings.Join(spec.ProvisionCmds, "\n")
		cfg.Provision = []LimaProvision{
			{Mode: "system", Script: script},
		}
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("marshal lima config: %w", err)
	}

	return string(data), nil
}

// parsePortRange parses a port range string like "3000:9999" into a LimaPortForward.
func parsePortRange(s string) (LimaPortForward, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return LimaPortForward{}, fmt.Errorf("invalid port range %q: expected format start:end", s)
	}
	start, err := strconv.Atoi(parts[0])
	if err != nil {
		return LimaPortForward{}, fmt.Errorf("invalid port start %q: %w", parts[0], err)
	}
	end, err := strconv.Atoi(parts[1])
	if err != nil {
		return LimaPortForward{}, fmt.Errorf("invalid port end %q: %w", parts[1], err)
	}
	if start > end {
		return LimaPortForward{}, fmt.Errorf("port start %d must be <= end %d", start, end)
	}
	if start < 1 || end > 65535 {
		return LimaPortForward{}, fmt.Errorf("ports must be between 1 and 65535")
	}
	return LimaPortForward{
		GuestPortRange: [2]int{start, end},
		HostPortRange:  [2]int{start, end},
	}, nil
}

var safePathRe = regexp.MustCompile(`^[a-zA-Z0-9_./-]+$`)

func validateSpec(spec api.VMSpec) error {
	if spec.Name == "" {
		return fmt.Errorf("name is required")
	}
	if err := validateName(spec.Name); err != nil {
		return fmt.Errorf("invalid name: %w", err)
	}
	if spec.CPU < 1 {
		return fmt.Errorf("cpu must be >= 1, got %d", spec.CPU)
	}
	if spec.Memory == "" {
		return fmt.Errorf("memory is required")
	}
	if spec.Disk == "" {
		return fmt.Errorf("disk is required")
	}
	for _, m := range spec.Mounts {
		if m.HostPath == "" {
			return fmt.Errorf("mount host_path is required")
		}
		cleaned := filepath.Clean(m.HostPath)
		if !safePathRe.MatchString(cleaned) {
			return fmt.Errorf("mount host_path %q contains invalid characters", m.HostPath)
		}
		if strings.Contains(m.HostPath, "..") {
			return fmt.Errorf("mount host_path %q must not contain ..", m.HostPath)
		}
	}
	if len(spec.ProvisionCmds) > 10 {
		return fmt.Errorf("too many provision commands (max 10, got %d)", len(spec.ProvisionCmds))
	}
	for i, cmd := range spec.ProvisionCmds {
		if len(cmd) > 4096 {
			return fmt.Errorf("provision command %d exceeds max length of 4096", i)
		}
	}
	return nil
}
