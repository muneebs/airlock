# airlock

A CLI tool that runs npm/pnpm/bun projects inside a Lima VM on macOS. The VM has no access to your home directory, SSH keys, or anything else on your host. Only the project directory you explicitly pass in gets mounted.

Built for two problems:
1. Vetting npm packages before trusting them with your filesystem
2. Running dev environments in isolation so a compromised dependency can't reach beyond your project

## Requirements

- macOS (Apple Silicon or Intel)
- [Lima](https://lima-vm.io/) (`brew install lima`)
- [jq](https://jqlang.github.io/jq/) (`brew install jq`)

## Install

```bash
cp airlock ~/bin/airlock
chmod +x ~/bin/airlock
```

## Quick start

```bash
# Create the VM (installs Node.js 22, pnpm, bun, Claude Code)
airlock setup

# Audit a project's dependencies without running any install scripts
airlock npm ./my-project

# Mount a project and start developing inside the VM
airlock pnpm ./my-project dev

# Run Claude Code airlocked to a single project directory
airlock claude ./my-project
```

## Security modes

### audit (default)

No host mounts at all. Copies `package.json` and the lockfile into the VM, installs without lifecycle scripts, runs `npm audit`, and shows which packages have install scripts. Nothing from the VM can touch your host filesystem.

```bash
airlock npm ./sketchy-lib
```

### full

Same isolation as audit, but installs with lifecycle scripts enabled. After install, the network gets locked (iptables DROP on OUTPUT). You get dropped into a shell to observe what the scripts did and whether anything tries to phone home.

```bash
airlock npm ./sketchy-lib full
```

### dev

Mounts your project directory into the VM read-write via virtiofs. Changes sync both ways in real time. Ports 3000-9999 are forwarded to localhost by default. Multiple projects can be mounted simultaneously.

```bash
airlock pnpm ./frontend dev
airlock pnpm ./api dev 8080:8080
airlock pnpm ./worker dev 9000:9000 "pnpm start"
```

### claude

Mounts the project directory and runs Claude Code inside the VM. Network stays open (Claude Code needs API access). Auth credentials are copied from your host `~/.claude` directory into the VM, but the VM can't modify your host auth config.

Claude Code can read and write files in the mounted project. It has zero access to the rest of your filesystem.

```bash
airlock claude .
airlock claude ./my-app
airlock claude ./my-app --print "fix the failing tests"
```

## Commands

```
airlock setup                                    Create and provision the VM
airlock <npm|pnpm|bun> <dir>                     Audit (isolated)
airlock <npm|pnpm|bun> <dir> full                Install with scripts + locked network
airlock <npm|pnpm|bun> <dir> dev                 Dev mode (mount + ports)
airlock <npm|pnpm|bun> <dir> dev <ports>         Custom port range
airlock <npm|pnpm|bun> <dir> dev <ports> <cmd>   Dev mode + run command
airlock claude <dir>                             Claude Code (airlocked)
airlock claude <dir> <args>                      Claude Code with arguments
airlock list                                     Show mounted projects
airlock remove <name>                            Unmount a project
airlock shell                                    Shell into the VM
airlock run <command>                            Run a command in the projects dir
airlock lock                                     Block outbound network
airlock unlock                                   Re-enable outbound network
airlock status                                   VM status, mounts, network state
airlock stop                                     Stop the VM
airlock reset                                    Reset to clean baseline
airlock destroy                                  Delete everything
airlock version                                  Print version
```

## Multiple projects

Each project mounts at `/home/airlock/projects/<name>` inside the VM. If two directories share a basename, the second gets a suffix (`api`, `api-2`).

```bash
airlock pnpm ./frontend dev
airlock pnpm ./api dev 8080:8080

airlock list
# frontend -> /home/airlock/projects/frontend
# api      -> /home/airlock/projects/api

airlock shell
cd projects/frontend && pnpm dev
# or
cd ../api && pnpm test

airlock remove api
```

Adding a project restarts the VM (~10 seconds) since Lima can't hot-add mounts.

## Monorepos

Mount the monorepo root. The default port range (3000-9999) covers multiple services. pnpm workspaces, turborepo, nx all work as expected since the entire repo is mounted.

```bash
airlock pnpm ./my-monorepo dev
# inside the VM:
pnpm --filter ./apps/web dev &
pnpm --filter ./apps/api dev &
```

Or run everything at once if your root `package.json` has a dev script:

```bash
airlock pnpm ./my-monorepo dev 3000:9999 "pnpm dev"
```

## Network control

```bash
# Lock outbound traffic (only DNS resolution allowed)
airlock lock

# Unlock
airlock unlock
```

In `full` mode, the network is locked automatically after install. In `dev` and `claude` modes, the network stays open.

## What's in the VM

The `setup` command creates an Ubuntu 24.04 VM using Apple's Virtualization.framework (`vmType: vz`) and installs:

- Node.js 22 LTS
- pnpm
- bun (non-fatal if install fails)
- Claude Code (non-fatal if install fails)
- git, curl, jq, iptables

A dedicated `airlock` user runs all project commands. No root access from within the airlock.

## How it works

Lima creates a lightweight Linux VM on macOS using Apple's Hypervisor.framework. This gives real hypervisor-level isolation, not just container-level process isolation like Docker.

The airlock script manages the VM lifecycle and maintains a mount registry at `~/.airlock/mounts.json`. When you add or remove projects, it rewrites `~/.lima/npm-airlock/lima.yaml` and restarts the VM. Host directories are mounted via virtiofs at their original paths inside the VM, with symlinks at `/home/airlock/projects/<name>` for convenience.

A clean baseline is saved at setup time. `airlock reset` restores the VM to that state and clears all mounts.

## Files

```
~/bin/airlock                      The CLI script
~/.lima/npm-airlock/               Lima VM instance
~/.lima/npm-airlock-clean/         Clean baseline for reset
~/.airlock/mounts.json             Mount registry
```

## Limitations

- macOS only (Lima with vz requires Apple's Virtualization.framework)
- Adding/removing mounts requires a VM restart (~10s)
- The `airlock` user's UID is mapped to your host UID so file permissions work, but this can conflict if the Lima default user already has that UID
- `audit` and `full` modes copy only `package.json`, the lockfile, and config files into the VM. Source code is not copied. These modes are for package vetting, not running the project.
- bun and Claude Code installs are non-fatal during setup. If they fail, npm and pnpm still work.
