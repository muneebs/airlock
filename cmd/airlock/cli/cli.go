package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/muneebs/airlock/cmd/airlock/cli/tui"
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

var version = "0.1.0"

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

func Execute() error {
	return ExecuteContext(context.Background())
}

// ExecuteContext runs the root command with the given context. The context
// is propagated to all subcommands so SIGINT/SIGTERM can cancel in-flight
// work and trigger rollback paths.
func ExecuteContext(ctx context.Context) error {
	deps, err := assembleDependencies()
	if err != nil {
		return fmt.Errorf("initialize: %w", err)
	}
	return newRootCmd(os.Stdout, os.Stderr, deps).ExecuteContext(ctx)
}

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

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func newRootCmd(stdout, stderr io.Writer, deps *Dependencies) *cobra.Command {
	root := &cobra.Command{
		Use:           "airlock",
		Short:         "Run any software in an isolated airlock environment",
		Long:          "airlock creates lightweight Lima VMs on macOS to run software in isolation.\nIt supports npm/pnpm/bun projects, Go binaries, Rust crates, Python scripts,\nDocker containers, and more — all with VM-level security and zero host access.",
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
		Use:   "setup [flags] [name]",
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

			spec := api.SandboxSpec{
				Name:    name,
				Profile: cfg.Security.Profile,
				CPU:     &cfg.VM.CPU,
				Memory:  cfg.VM.Memory,
				Disk:    cfg.VM.Disk,
				Ports:   cfg.Dev.Ports,
			}

			// createStage is updated by Manager.CreateWithProgress as it
			// walks through its internal phases (validate → resolve →
			// provider.Create → provider.Start → apply network policy →
			// save state). The spinner renders this in its suffix so the
			// user can see exactly which sub-step is currently running and
			// distinguish a legitimately slow step (boot) from a hung one.
			var createStage atomic.Value
			createStage.Store("starting")

			phases := []tui.Phase{
				{
					Label:     "Creating VM " + name + " (fresh Ubuntu boot takes 5–7 min)",
					DoneLabel: "VM " + name + " created and booted",
					Action: func() error {
						_, err := deps.Manager.CreateWithOptions(ctx, spec, api.CreateOptions{
							Progress: func(stage string) {
								createStage.Store(stage)
							},
							SkipNetworkPolicy: true,
						})
						return err
					},
					Status: func() string {
						s, _ := createStage.Load().(string)
						return s
					},
				},
			}
			for _, step := range deps.Provisioner.ProvisionSteps(name, nodeVersion) {
				step := step
				phases = append(phases, tui.Phase{
					Label:     step.Label,
					DoneLabel: step.Label,
					Action:    func() error { return step.Run(ctx) },
				})
			}
			phases = append(phases, tui.Phase{
				Label:     "Applying network policy",
				DoneLabel: "Network policy applied",
				Action: func() error {
					return deps.Manager.ApplyNetworkProfile(ctx, name)
				},
			})
			phases = append(phases, tui.Phase{
				Label:     "Saving clean snapshot",
				DoneLabel: "Snapshot saved",
				Action: func() error {
					return deps.Provisioner.SnapshotClean(ctx, name)
				},
			})

			if err := tui.RunPhases(phases); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "\n%s\n", tui.SuccessLine("VM %q is ready to use.", name))
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
	var jsonOutput bool

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

			var info api.SandboxInfo
			var createErr error
			if jsonOutput {
				info, createErr = deps.Manager.Create(ctx, spec)
			} else {
				createErr = tui.RunSpinner("Creating sandbox "+name, "Sandbox "+name+" created", func() error {
					var err error
					info, err = deps.Manager.Create(ctx, spec)
					return err
				})
			}
			if createErr != nil {
				return createErr
			}

			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(info)
			}

			fmt.Fprintln(cmd.OutOrStdout())
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
	cmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output as JSON")

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
		Use:   "shell [name]",
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
				fmt.Fprintln(cmd.OutOrStdout(), tui.EmptyState("No sandboxes found. Run 'airlock setup' to create one."))
				return nil
			}

			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(sandboxes)
			}

			table := tui.NewTable(
				tui.TableColumn{Header: "NAME", Width: 20},
				tui.TableColumn{Header: "STATE", Width: 10},
				tui.TableColumn{Header: "PROFILE", Width: 10},
				tui.TableColumn{Header: "RUNTIME", Width: 10},
				tui.TableColumn{Header: "CREATED", Width: 16},
			)

			for _, sb := range sandboxes {
				stateStr := tui.StateColor(string(sb.State)).Render(string(sb.State))
				profStr := tui.ProfileColor(sb.Profile).Render(sb.Profile)
				table.AddRow(sb.Name, stateStr, profStr, sb.Runtime, sb.CreatedAt.Format("2006-01-02 15:04"))
			}

			fmt.Fprint(cmd.OutOrStdout(), table.Render())
			return nil
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

			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", tui.SuccessLine("Mount %q removed.", mountName))
			return nil
		},
	}

	cmd.Flags().StringVarP(&sandboxName, "sandbox", "s", "", "Sandbox name (required for multi-sandbox setups)")
	_ = cmd.MarkFlagRequired("sandbox")

	return cmd
}

func newStatusCmd(deps *Dependencies) *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
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

			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(info)
			}

			printSandboxInfo(cmd.OutOrStdout(), info)

			mounts, _ := deps.Mounts.List(ctx, name)
			if len(mounts) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "\n%s\n", tui.SectionHeader("Mounts"))
				for _, m := range mounts {
					writable := "read-only"
					if m.Writable {
						writable = "read-write"
					}
					fmt.Fprintf(cmd.OutOrStdout(), "  %s %s %s %s (%s)\n",
						tui.Bullet.String(), m.HostPath, tui.Arrow.String(), m.VMPath, writable)
				}
			}

			locked, err := deps.Network.IsLocked(ctx, name)
			if err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "\n%s\n", tui.SectionHeader("Network"))
				if locked {
					fmt.Fprintf(cmd.OutOrStdout(), "  %s %s\n", tui.Bullet.String(), tui.LockColor(true).Render("locked (outbound blocked)"))
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "  %s %s\n", tui.Bullet.String(), tui.LockColor(false).Render("unlocked (outbound allowed)"))
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "Output as JSON")

	return cmd
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

			if err := tui.RunSpinner("Stopping sandbox "+name, "Sandbox "+name+" stopped", func() error {
				return deps.Manager.Stop(ctx, name)
			}); err != nil {
				return fmt.Errorf("stop %q: %w", name, err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", tui.SuccessLine("Sandbox %q stopped.", name))
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

			if err := tui.RunSpinner("Resetting sandbox "+name, "Sandbox "+name+" reset", func() error {
				return deps.Manager.Reset(ctx, name)
			}); err != nil {
				return fmt.Errorf("reset %q: %w", name, err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", tui.SuccessLine("Sandbox %q reset to clean state.", name))
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

			if err := tui.RunSpinner("Destroying sandbox "+name, "Sandbox "+name+" destroyed", func() error {
				return deps.Manager.Destroy(ctx, name)
			}); err != nil {
				return fmt.Errorf("destroy %q: %w", name, err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", tui.SuccessLine("Sandbox %q destroyed.", name))
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

			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", tui.SuccessLine("Network locked for sandbox %q. All outbound traffic blocked except DNS.", name))
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

			fmt.Fprintf(cmd.OutOrStdout(), "%s\n", tui.SuccessLine("Network unlocked for sandbox %q. Outbound traffic is allowed.", name))
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
			table := tui.NewTable(
				tui.TableColumn{Header: "PROFILE", Width: 12},
				tui.TableColumn{Header: "DESCRIPTION", Width: 80},
			)
			for _, name := range names {
				p, err := deps.Profiles.Get(name)
				if err != nil {
					continue
				}
				profileStyle := tui.ProfileColor(p.Name)
				table.AddRow(profileStyle.Render(p.Name), p.Description)
			}
			fmt.Fprint(cmd.OutOrStdout(), table.Render())
			return nil
		},
	}
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print airlock version",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "airlock %s\n", tui.Bold.Render(version))
			return nil
		},
	}
}

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
	fmt.Fprintf(w, "%s\n", tui.SectionHeader("Sandbox"))
	fmt.Fprintf(w, "  %s\n", tui.StyledKeyValue("Name", info.Name, tui.KeyStyle))
	fmt.Fprintf(w, "  %s\n", tui.StyledKeyValue("State", tui.StateColor(string(info.State)).Render(string(info.State)), tui.KeyStyle))
	fmt.Fprintf(w, "  %s\n", tui.StyledKeyValue("Profile", tui.ProfileColor(info.Profile).Render(info.Profile), tui.KeyStyle))
	fmt.Fprintf(w, "  %s\n", tui.StyledKeyValue("Runtime", info.Runtime, tui.KeyStyle))
	if info.Source != "" {
		fmt.Fprintf(w, "  %s\n", tui.StyledKeyValue("Source", info.Source, tui.KeyStyle))
	}
	fmt.Fprintf(w, "  %s\n", tui.StyledKeyValue("CPU", fmt.Sprintf("%d", info.CPU), tui.KeyStyle))
	fmt.Fprintf(w, "  %s\n", tui.StyledKeyValue("Memory", info.Memory, tui.KeyStyle))
	fmt.Fprintf(w, "  %s\n", tui.StyledKeyValue("Disk", info.Disk, tui.KeyStyle))
	if info.Ephemeral {
		fmt.Fprintf(w, "  %s\n", tui.StyledKeyValue("Ephemeral", tui.WarningF.Render("true"), tui.KeyStyle))
	}
	fmt.Fprintf(w, "  %s\n", tui.StyledKeyValue("Created", info.CreatedAt.Format("2006-01-02 15:04:05"), tui.KeyStyle))
}

func networkState(locked bool) string {
	if locked {
		return "locked (outbound blocked)"
	}
	return "unlocked (outbound allowed)"
}
