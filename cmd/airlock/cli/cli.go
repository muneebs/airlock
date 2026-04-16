// Package cli defines the airlock command-line interface using Cobra.
// It wires dependencies through interfaces, never concrete types.
package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

const version = "0.1.0"

// Execute runs the root command.
func Execute() error {
	return newRootCmd(os.Stdout, os.Stderr).Execute()
}

// newRootCmd creates the root command with all subcommands.
func newRootCmd(stdout, stderr io.Writer) *cobra.Command {
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
		newSetupCmd(),
		newSandboxCmd(),
		newShellCmd(),
		newListCmd(),
		newRemoveCmd(),
		newStatusCmd(),
		newStopCmd(),
		newResetCmd(),
		newDestroyCmd(),
		newLockCmd(),
		newUnlockCmd(),
		newVersionCmd(),
	)

	return root
}

func newSetupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "setup",
		Short: "Create and provision the airlock VM",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "setup: not yet implemented")
			return nil
		},
	}
}

func newSandboxCmd() *cobra.Command {
	var profile string
	var runtime string
	var docker bool
	var ephemeral bool
	var ports string

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
			fmt.Fprintf(cmd.OutOrStdout(), "sandbox %q: profile=%s runtime=%s docker=%v ephemeral=%v ports=%s\n",
				args[0], profile, runtime, docker, ephemeral, ports)
			fmt.Fprintln(cmd.OutOrStdout(), "sandbox: not yet implemented")
			return nil
		},
	}

	cmd.Flags().StringVarP(&profile, "profile", "p", "cautious", "Security profile: strict, cautious, dev, trusted")
	cmd.Flags().StringVarP(&runtime, "runtime", "r", "", "Override auto-detected runtime: node, go, rust, python, docker, compose, make, dotnet")
	cmd.Flags().BoolVar(&docker, "docker", false, "Allow Docker access inside the sandbox")
	cmd.Flags().BoolVar(&ephemeral, "ephemeral", false, "Destroy sandbox on exit")
	cmd.Flags().StringVar(&ports, "ports", "3000:9999", "Port range to forward (e.g. 3000:9999)")

	return cmd
}

func newShellCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "shell",
		Short: "Shell into the airlock VM",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "shell: not yet implemented")
			return nil
		},
	}
}

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Show all mounted projects",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "list: not yet implemented")
			return nil
		},
	}
}

func newRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Unmount a project",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "remove %q: not yet implemented\n", args[0])
			return nil
		},
	}
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show VM status, mounts, network state",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "status: not yet implemented")
			return nil
		},
	}
}

func newStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop the airlock VM",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "stop: not yet implemented")
			return nil
		},
	}
}

func newResetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reset",
		Short: "Reset to clean baseline (clears all mounts)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "reset: not yet implemented")
			return nil
		},
	}
}

func newDestroyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "destroy",
		Short: "Delete the airlock VM and all data",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "destroy: not yet implemented")
			return nil
		},
	}
}

func newLockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Block all outbound network traffic",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "lock: not yet implemented")
			return nil
		},
	}
}

func newUnlockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unlock",
		Short: "Re-enable outbound network traffic",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), "unlock: not yet implemented")
			return nil
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
