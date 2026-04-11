# airlock [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A CLI tool that runs npm/pnpm/bun projects inside a Lima VM on macOS. The VM has no access to your home directory, SSH keys, or anything else on your host. Only the project directory you explicitly pass in gets mounted.

Built for two problems:
1. Vetting npm packages before trusting them with your filesystem
2. Running dev environments in isolation so a compromised dependency can't reach beyond your project

---

## Install

**One-liner:**

```bash
curl -fsSL https://raw.githubusercontent.com/muneebs/airlock/main/install.sh | bash
```

This installs `lima`, `jq`, `yq`, and the `airlock` CLI to `~/.local/bin`.

**From source:**

```bash
git clone https://github.com/muneebs/airlock
cd airlock
bash install.sh
```

**Requirements:** macOS (Apple Silicon or Intel). `yq v4` is only required if you use `airlock.toml`.

---

## Quick start

```bash
# Create the VM (one-time — installs Node.js 22, pnpm, bun, Claude Code)
airlock setup

# Audit a project's dependencies without running any install scripts
airlock npm ./my-project

# Mount a project and start developing inside the VM
airlock pnpm ./my-project dev

# Run Claude Code airlocked to a single project directory
airlock claude ./my-project
```

---

## Security modes

### audit (default)

No host mounts. Copies `package.json` and the lockfile into the VM, installs without lifecycle scripts, runs `npm audit`, and shows which packages have install scripts. Nothing from the VM can touch your host filesystem.

```bash
airlock npm ./sketchy-lib
```

### full

Same isolation as audit, but installs with lifecycle scripts enabled. After install, the network gets locked (iptables DROP on OUTPUT). You get dropped into a shell to observe what the scripts did and whether anything tries to phone home.

```bash
airlock npm ./sketchy-lib full
```

### dev

Mounts your project directory into the VM read-write via virtiofs. Changes sync both ways in real time. Ports 3000-9999 are forwarded to localhost by default.

```bash
airlock pnpm ./my-app dev
airlock pnpm ./my-app dev 8080:8080          # custom port range
airlock pnpm ./my-app dev 3000:3000 "pnpm dev"  # run command immediately
```

Multiple projects can be mounted simultaneously — each gets its own path at `/home/airlock/projects/<name>`:

```bash
airlock pnpm ./frontend dev
airlock pnpm ./api dev 8080:8080

airlock shell
# cd projects/frontend && pnpm dev
# cd ../api && pnpm test

airlock remove api   # unmount when done
```

Adding a project restarts the VM (~10 seconds) since Lima can't hot-add mounts.

### claude

Mounts the project directory and runs Claude Code inside the VM. Network stays open (Claude Code needs API access). Auth credentials are copied from your host `~/.claude` into the VM, but the VM can't modify your host auth config.

Claude Code can read and write files in the mounted project. It has zero access to the rest of your filesystem.

```bash
airlock claude .
airlock claude ./my-app
airlock claude ./my-app --print "fix the failing tests"
```

---

## Per-project configuration

Create an `airlock.toml` in your project directory to set defaults for ports, startup command, extra mounts, and VM resources. All fields are optional — omit any you don't need.

```toml
[vm]
cpu = 2
memory = "4GiB"
disk = "20GiB"
node_version = 22

[dev]
ports = "3000:3000"
command = "pnpm dev"

[services]
compose = "./docker-compose.yml"   # started automatically before dev command

[[mounts]]
path = "./api"

[[mounts]]
path = "./shared"
```

When `[services] compose` is set, `airlock dev` runs `docker compose up -d` inside the VM before starting your app. Services are reachable from your app code at `localhost:<port>` as normal. To also reach a service from your host (e.g. a DB client), include its port in `[dev] ports`.

CLI arguments override config values, which override built-in defaults:

```
CLI arg  >  airlock.toml  >  built-in default
```

**Monorepos:** use `airlock.toml` instead of long CLI invocations:

```toml
[dev]
ports = "3000:9999"
command = "pnpm dev"
```

```bash
airlock pnpm ./my-monorepo dev
```

pnpm workspaces, turborepo, and nx all work since the entire repo is mounted.

---

## Network control

```bash
airlock lock     # block all outbound traffic (DNS still works)
airlock unlock   # re-enable outbound
```

`full` mode locks the network automatically after install. `dev` and `claude` modes leave it open.

---

## Commands

```
airlock setup                                    Create and provision the VM

airlock <npm|pnpm|bun> <dir>                     Audit (isolated, no host mounts)
airlock <npm|pnpm|bun> <dir> full                Install with scripts + locked network
airlock <npm|pnpm|bun> <dir> dev                 Dev mode (mount + ports)
airlock <npm|pnpm|bun> <dir> dev <ports>         Custom port range
airlock <npm|pnpm|bun> <dir> dev <ports> <cmd>   Dev mode + run command immediately

airlock claude <dir>                             Run Claude Code (airlocked)
airlock claude <dir> <args>                      Run Claude Code with arguments

airlock list                                     Show mounted projects
airlock remove <name>                            Unmount a project
airlock shell                                    Shell into the VM (projects dir)
airlock run <command>                            Run a command in the projects dir
airlock lock                                     Block outbound network
airlock unlock                                   Re-enable outbound network
airlock status                                   VM status, mounts, network state
airlock stop                                     Stop the VM
airlock reset                                    Reset to clean baseline (clears all mounts)
airlock destroy                                  Delete everything
airlock version                                  Print version
```

---

## Reference

### What's in the VM

`airlock setup` creates an Ubuntu 24.04 VM using Apple's Virtualization.framework and installs:

- Node.js 22 LTS (configurable via `airlock.toml`)
- pnpm, bun
- Docker CE (with `docker compose` v2)
- Claude Code
- git, curl, jq, iptables

bun and Claude Code installs are non-fatal. If they fail, npm and pnpm still work.

### How it works

Lima creates a lightweight Linux VM on macOS using Apple's Hypervisor.framework — real hypervisor-level isolation, not container-level process isolation like Docker.

airlock manages the VM lifecycle and a mount registry at `~/.airlock/mounts.json`. When you add or remove projects, it rewrites `~/.lima/npm-airlock/lima.yaml` and restarts the VM. Host directories are mounted via virtiofs at their original paths inside the VM, with symlinks at `/home/airlock/projects/<name>` for convenience.

A clean baseline is saved at setup time. `airlock reset` restores the VM to that state and clears all mounts.

### Files

```
~/.local/bin/airlock               The CLI script
~/.lima/npm-airlock/               Lima VM instance
~/.lima/npm-airlock-clean/         Clean baseline for reset
~/.airlock/mounts.json             Mount registry
<project>/airlock.toml             Optional per-project config
```

### Limitations

- macOS only (Lima with vz requires Apple's Virtualization.framework)
- Adding/removing mounts requires a VM restart (~10s)
- The `airlock` user's UID is mapped to your host UID so file permissions work, but this can conflict if the Lima default user already has that UID
- `audit` and `full` modes copy only `package.json`, the lockfile, and config files — not source code. These modes are for package vetting, not running the project.
- `airlock.toml` requires yq v4 (mikefarah). If yq is missing and a config file is present, airlock exits with an error pointing to `install.sh`.
