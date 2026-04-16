// Package cli defines the airlock command-line interface using Cobra.
// It wires dependencies through interfaces, never concrete types.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/muneebs/airlock/internal/api"
	"github.com/muneebs/airlock/internal/config"
	"github.com/muneebs/airlock/internal/detect"
	"github.com/muneebs/airlock/internal/mount"
	"github.com/muneebs/airlock/internal/network"
	"github.com/muneebs/airlock/internal/profile"
	"github.com/muneebs/airlock/internal/sandbox"
	"github.com/muneebs/airlock/internal/vm/lima"
	"github.com/spf13/cobra"
)

const version = "0.1.0"

// Dependencies holds all injectable dependencies for CLI commands.
// Every field is an interface — concrete types are assembled in
// assembleDependencies and never referenced in command handlers.
type Dependencies struct {
	Manager     api.SandboxManager
	Provider    api.Provider
	Provisioner api.Provisioner
	Sheller     api.ShellProvider
	Mounts      api.MountManager
	Network     api.NetworkController
	Profiles    api.ProfileRegistry
	ConfigDir   string
	IsTTY       bool
}

// Execute runs the root command. It assembles all dependencies and injects them
// into CLI subcommands. The CLI depends only on interfaces (Principle 5:
// Dependency Inversion).
func Execute() error {
	deps, err := assembleDependencies()
	if err != nil {
		return fmt.Errorf("initialize: %w", err)
	}
	return newRootCmd(os.Stdout, os.Stderr, deps).Execute()
}

// assembleDependencies constructs all production dependencies following
// Dependency Inversion: high-level depends on interfaces, low-level implements them.
func assembleDependencies() (*Dependencies, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("get home dir: %w", err)
	}
	configDir := filepath.Join(home, ".airlock")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}

	limaProvider, err := lima.NewLimaProvider()
	if err != nil {
		return nil, fmt.Errorf("init lima provider: %w", err)
	}

	detector := detect.NewCompositeDetector()
	profiles := profile.NewRegistry()

	mountStore, err := mount.NewJSONStore(filepath.Join(configDir, "mounts.json"))
	if err != nil {
		return nil, fmt.Errorf("init mount store: %w", err)
	}

	storePath := filepath.Join(configDir, "sandboxes.json")

	networkCtrl := network.NewLimaController()

	mgr, err := sandbox.NewManager(
		limaProvider,
		limaProvider,
		detector,
		profiles,
		mountStore,
		networkCtrl,
		storePath,
	)
	if err != nil {
		return nil, fmt.Errorf("init sandbox manager: %w", err)
	}

	return &Dependencies{
		Manager:     mgr,
		Provider:    limaProvider,
		Provisioner: limaProvider,
		Sheller:     limaProvider,
		Mounts:      mountStore,
		Network:     networkCtrl,
		Profiles:    profiles,
		ConfigDir:   configDir,
		IsTTY:       isTerminal(os.Stdout),
	}, nil
}

// isTerminal checks whether the given file is a terminal (TTY).
// Used to decide whether to prompt for credential copying.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// newRootCmd creates the root command with all subcommands.
func newRootCmd(stdout, stderr io.Writer, deps *Dependencies) *cobra.Command {
	root := &cobra.Command{
		Use:   "airlock",
		Short: "Run any software in an isolated airlock environment",
		Long: `airlock creates lightweight Lima VMs on macOS to run software in isolation.
It supports npm/pnpm/bun projects, Go binaries, Rust crates, Python scripts,
Docker containers, and more — all with VM-level security and zero host access.`,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.SetOut(stdout)
	root.SetErr(stderr)

	root.AddCommand(
		newSetupCmd(deps),
		newSandboxCmd(deps),
		newRunCmd(deps),
		newShellCmd(deps),
		newListCmd(deps),
		newRemoveCmd(deps),
		newStatusCmd(deps),
		newStopCmd(deps),
		newResetCmd(deps),
		newDestroyCmd(deps),
		newLockCmd(deps),
		newUnlockCmd(deps),
		newConfigCmd(),
		newProfileCmd(deps),
		newVersionCmd(),
	)

	return root
}

func newSetupCmd(deps *Dependencies) *cobra.Command {
	var nodeVersion int

	cmd := &cobra.Command{
		Use:   "setup [flags] <name>",
		Short: "Create and provision the airlock VM",
		Long: `Create a fresh Lima VM, install system packages and development tools,
then take a clean snapshot for future resets. This is the first command to run
before creating any sandboxes.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			name := "airlock"
			if len(args) > 0 {
				name = args[0]
			}

			if nodeVersion <= 0 {
				nodeVersion = 22
			}

			cfg, err := config.Load(".")
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			cpu := cfg.VM.CPU
			spec := api.SandboxSpec{
				Name:    name,
				Profile: cfg.Security.Profile,
				CPU:     &cpu,
				Memory:  cfg.VM.Memory,
				Disk:    cfg.VM.Disk,
				Ports:   cfg.Dev.Ports,
			}

			info, err := deps.Manager.Create(ctx, spec)
			if err != nil {
				return fmt.Errorf("create VM: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "VM %q created (state=%s). Provisioning...\n", info.Name, info.State)

			if err := deps.Provisioner.ProvisionVM(ctx, name, nodeVersion); err != nil {
				return fmt.Errorf("provision VM: %w", err)
			}

			if err := deps.Provisioner.SnapshotClean(ctx, name); err != nil {
				return fmt.Errorf("snapshot: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "VM %q provisioned and snapshot saved.\n", name)
			return nil
		},
	}

	cmd.Flags().IntVar(&nodeVersion, "node-version", 22, "Node.js major version to install")

	return cmd
}

func newSandboxCmd(deps *Dependencies) *cobra.Command {
	var sandboxProfile string
	var runtime string
	var docker bool
	var ephemeral bool
	var ports string
	var name string

	cmd := &cobra.Command{
		Use:   "sandbox [flags] <path-or-url>",
		Short: "Create an isolated sandbox for a project or GitHub repo",
		Long: `Create an isolated sandbox environment. Supports local directories
and GitHub URLs (gh:user/repo or https://github.com/user/repo).

Auto-detects the runtime if not specified with --runtime.

Security profiles:
  strict    No host mounts, network locked, no Docker. For untrusted software.
  cautious  Read-only host mounts, network locked after install, restricted Docker. Default.
  dev       Read-write project mount, open network, Docker allowed. For development.
  trusted   Full access. Only for software you author.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			source := args[0]
			if name == "" {
				name = deriveSandboxName(source)
			}

			cfg, err := config.Load(".")
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			cpu := cfg.VM.CPU
			memory := cfg.VM.Memory
			disk := cfg.VM.Disk
			if ports == "" {
				ports = cfg.Dev.Ports
			}

			profName := sandboxProfile
			if profName == "" {
				profName = cfg.Security.Profile
			}

			spec := api.SandboxSpec{
				Name:      name,
				Source:    source,
				Runtime:   runtime,
				Profile:   profName,
				Ephemeral: ephemeral,
				Docker:    docker,
				CPU:       &cpu,
				Memory:    memory,
				Disk:      disk,
				Ports:     ports,
			}

			info, err := deps.Manager.Create(ctx, spec)
			if err != nil {
				return fmt.Errorf("create sandbox: %w", err)
			}

			printSandboxInfo(cmd.OutOrStdout(), info)
			return nil
		},
	}

	cmd.Flags().StringVarP(&sandboxProfile, "profile", "p", "cautious", "Security profile: strict, cautious, dev, trusted")
	cmd.Flags().StringVarP(&runtime, "runtime", "r", "", "Override auto-detected runtime: node, go, rust, python, docker, compose, make, dotnet")
	cmd.Flags().BoolVar(&docker, "docker", false, "Allow Docker access inside the sandbox")
	cmd.Flags().BoolVar(&ephemeral, "ephemeral", false, "Mark sandbox as ephemeral (metadata only; use 'destroy' to clean up)")
	cmd.Flags().StringVar(&ports, "ports", "", "Port range to forward (e.g. 3000:9999), default from config")
	cmd.Flags().StringVarP(&name, "name", "n", "", "Sandbox name (default: derived from source path)")

	return cmd
}

func newRunCmd(deps *Dependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "run <name> <command...>",
		Short: "Run a command inside a sandbox",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			name := args[0]
			command := args[1:]

			output, err := deps.Manager.Run(ctx, name, command)
			if err != nil {
				return fmt.Errorf("run in %q: %w", name, err)
			}

			fmt.Fprint(cmd.OutOrStdout(), output)
			return nil
		},
	}
}

func newShellCmd(deps *Dependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "shell <name>",
		Short: "Shell into the airlock VM",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			name := "airlock"
			if len(args) > 0 {
				name = args[0]
			}

			if !deps.IsTTY {
				return fmt.Errorf("shell requires an interactive terminal (TTY)")
			}

			if err := deps.Provider.Start(ctx, name); err != nil {
				return fmt.Errorf("start VM %q: %w", name, err)
			}

			return deps.Sheller.Shell(ctx, name)
		},
	}
}

func newListCmd(deps *Dependencies) *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show all sandboxes",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			sandboxes, err := deps.Manager.List(ctx)
			if err != nil {
				return fmt.Errorf("list sandboxes: %w", err)
			}

			if len(sandboxes) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No sandboxes found.")
				return nil
			}

			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(sandboxes)
			}

			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tSTATE\tPROFILE\tRUNTIME\tCREATED")
			for _, sb := range sandboxes {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					sb.Name, sb.State, sb.Profile, sb.Runtime, sb.CreatedAt.Format("2006-01-02 15:04"))
			}
			return w.Flush()
		},
	}

	cmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output as JSON")

	return cmd
}

func newRemoveCmd(deps *Dependencies) *cobra.Command {
	var sandboxName string

	cmd := &cobra.Command{
		Use:   "remove <name>",
		Short: "Unmount a project from a sandbox",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			if sandboxName == "" {
				return fmt.Errorf("--sandbox flag is required")
			}

			mountName := args[0]
			if err := deps.Mounts.Unregister(ctx, sandboxName, mountName); err != nil {
				return fmt.Errorf("unmount %q: %w", mountName, err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Mount %q removed.\n", mountName)
			return nil
		},
	}

	cmd.Flags().StringVarP(&sandboxName, "sandbox", "s", "", "Sandbox name (required for multi-sandbox setups)")
	_ = cmd.MarkFlagRequired("sandbox")

	return cmd
}

func newStatusCmd(deps *Dependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "status [name]",
		Short: "Show sandbox status, mounts, network state",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			name := "airlock"
			if len(args) > 0 {
				name = args[0]
			}

			info, err := deps.Manager.Status(ctx, name)
			if err != nil {
				return fmt.Errorf("status %q: %w", name, err)
			}

			printSandboxInfo(cmd.OutOrStdout(), info)

			mounts, _ := deps.Mounts.List(ctx, name)
			if len(mounts) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "\nMounts:\n")
				for _, m := range mounts {
					fmt.Fprintf(cmd.OutOrStdout(), "  %s -> %s (writable=%v)\n", m.HostPath, m.VMPath, m.Writable)
				}
			}

			locked, err := deps.Network.IsLocked(ctx, name)
			if err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "\nNetwork: %s\n", networkState(locked))
			}

			return nil
		},
	}
}

func newStopCmd(deps *Dependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "stop [name]",
		Short: "Stop a sandbox",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			name := "airlock"
			if len(args) > 0 {
				name = args[0]
			}

			if err := deps.Manager.Stop(ctx, name); err != nil {
				return fmt.Errorf("stop %q: %w", name, err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Sandbox %q stopped.\n", name)
			return nil
		},
	}
}

func newResetCmd(deps *Dependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "reset [name]",
		Short: "Reset sandbox to clean baseline",
		Long: `Reset a sandbox to its clean snapshot state. The VM is stopped,
its disk is restored from the snapshot taken during setup, and the VM is restarted.
All changes since the last snapshot are lost.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			name := "airlock"
			if len(args) > 0 {
				name = args[0]
			}

			if err := deps.Manager.Reset(ctx, name); err != nil {
				return fmt.Errorf("reset %q: %w", name, err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Sandbox %q reset to clean state.\n", name)
			return nil
		},
	}
}

func newDestroyCmd(deps *Dependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "destroy [name]",
		Short: "Delete a sandbox and all its data",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			name := "airlock"
			if len(args) > 0 {
				name = args[0]
			}

			if err := deps.Manager.Destroy(ctx, name); err != nil {
				return fmt.Errorf("destroy %q: %w", name, err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Sandbox %q destroyed.\n", name)
			return nil
		},
	}
}

func newLockCmd(deps *Dependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "lock [name]",
		Short: "Block all outbound network traffic",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			name := "airlock"
			if len(args) > 0 {
				name = args[0]
			}

			if err := deps.Network.Lock(ctx, name); err != nil {
				return fmt.Errorf("lock network for %q: %w", name, err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Network locked for sandbox %q. All outbound traffic is blocked except DNS.\n", name)
			return nil
		},
	}
}

func newUnlockCmd(deps *Dependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "unlock [name]",
		Short: "Re-enable outbound network traffic",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			name := "airlock"
			if len(args) > 0 {
				name = args[0]
			}

			if err := deps.Network.Unlock(ctx, name); err != nil {
				return fmt.Errorf("unlock network for %q: %w", name, err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Network unlocked for sandbox %q. Outbound traffic is allowed.\n", name)
			return nil
		},
	}
}

func newConfigCmd() *cobra.Command {
	var showFormat string

	cmd := &cobra.Command{
		Use:   "config",
		Short: "Show or validate airlock configuration",
		Long: `Display the current airlock configuration resolved from the project
directory. If no config file exists, shows defaults. Supports --format=toml
or --format=yaml output.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(".")
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}

			switch showFormat {
			case "json":
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(cfg)
			case "toml":
				data, err := config.WriteTOML(cfg)
				if err != nil {
					return fmt.Errorf("serialize toml: %w", err)
				}
				fmt.Fprint(cmd.OutOrStdout(), string(data))
				return nil
			case "yaml":
				data, err := config.WriteYAML(cfg)
				if err != nil {
					return fmt.Errorf("serialize yaml: %w", err)
				}
				fmt.Fprint(cmd.OutOrStdout(), string(data))
				return nil
			default:
				return fmt.Errorf("unknown format %q (valid: json, toml, yaml)", showFormat)
			}
		},
	}

	cmd.Flags().StringVarP(&showFormat, "format", "f", "yaml", "Output format: json, toml, yaml")

	return cmd
}

func newProfileCmd(deps *Dependencies) *cobra.Command {
	return &cobra.Command{
		Use:   "profile",
		Short: "List available security profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			names := deps.Profiles.List()
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "PROFILE\tDESCRIPTION")
			for _, name := range names {
				p, err := deps.Profiles.Get(name)
				if err != nil {
					continue
				}
				fmt.Fprintf(w, "%s\t%s\n", p.Name, p.Description)
			}
			return w.Flush()
		},
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print airlock version",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "airlock "+version)
			return nil
		},
	}
}

// deriveSandboxName creates a sandbox name from a source path or URL.
func deriveSandboxName(source string) string {
	if strings.HasPrefix(source, "gh:") {
		parts := strings.SplitN(strings.TrimPrefix(source, "gh:"), "/", 2)
		if len(parts) == 2 {
			return sanitizeName(strings.TrimSuffix(parts[1], ".git"))
		}
		return sanitizeName(strings.TrimPrefix(source, "gh:"))
	}
	if strings.HasPrefix(source, "https://github.com/") {
		parts := strings.SplitN(strings.TrimPrefix(source, "https://github.com/"), "/", 3)
		if len(parts) >= 2 {
			return sanitizeName(strings.TrimSuffix(parts[1], ".git"))
		}
	}
	base := filepath.Base(source)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	if base == "" || base == "." || base == ".." {
		return "sandbox"
	}
	return sanitizeName(base)
}

func sanitizeName(name string) string {
	var b strings.Builder
	for i, r := range name {
		if i == 0 && !isAlpha(r) && r != '_' {
			b.WriteByte('_')
			continue
		}
		if isAlphaNum(r) || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
		}
	}
	result := b.String()
	if result == "" {
		return "sandbox"
	}
	return result
}

func isAlpha(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

func isAlphaNum(r rune) bool {
	return isAlpha(r) || (r >= '0' && r <= '9')
}

func printSandboxInfo(w io.Writer, info api.SandboxInfo) {
	fmt.Fprintf(w, "Name:      %s\n", info.Name)
	fmt.Fprintf(w, "State:     %s\n", info.State)
	fmt.Fprintf(w, "Profile:   %s\n", info.Profile)
	fmt.Fprintf(w, "Runtime:   %s\n", info.Runtime)
	fmt.Fprintf(w, "Source:    %s\n", info.Source)
	fmt.Fprintf(w, "CPU:       %d\n", info.CPU)
	fmt.Fprintf(w, "Memory:    %s\n", info.Memory)
	fmt.Fprintf(w, "Disk:      %s\n", info.Disk)
	fmt.Fprintf(w, "Ephemeral: %v\n", info.Ephemeral)
	fmt.Fprintf(w, "Created:   %s\n", info.CreatedAt.Format("2006-01-02 15:04:05"))
}

func networkState(locked bool) string {
	if locked {
		return "locked (outbound blocked)"
	}
	return "unlocked (outbound allowed)"
}
