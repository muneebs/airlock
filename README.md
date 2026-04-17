# airlock [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Run untrusted software in isolated Lima VMs on macOS. Each sandbox gets its own VM with configurable network and filesystem restrictions — no access to your home directory, SSH keys, or anything you don't explicitly allow.

## Install

**One-liner (recommended):**

```bash
curl -fsSL https://raw.githubusercontent.com/muneebs/airlock/main/install.sh | bash
```

Downloads a pre-built binary from [GitHub Releases](https://github.com/muneebs/airlock/releases).

**From source (requires Go 1.23+):**

```bash
git clone https://github.com/muneebs/airlock
cd airlock
make install
```

**Prerequisites:** macOS (Apple Silicon or Intel) with [Lima](https://github.com/lima-vm/lima) installed.

## Quick start

```bash
# Create and provision the VM (one-time)
airlock setup

# Create a sandbox for a local project
airlock sandbox ./my-project

# Create a sandbox from a GitHub repo
airlock sandbox gh:user/repo

# Run a command inside it
airlock run my-project -- npm test

# Shell into it
airlock shell my-project

# Lock the network (block all outbound except DNS)
airlock lock my-project

# Check status
airlock status my-project

# Reset to clean baseline
airlock reset my-project

# Delete everything
airlock destroy my-project
```

## Commands

| Command | Description |
|---------|-------------|
| `airlock setup [name]` | Create and provision a VM, then take a clean snapshot |
| `airlock sandbox <path-or-url>` | Create an isolated sandbox |
| `airlock run <name> <command...>` | Run a command inside a sandbox |
| `airlock shell [name]` | Open an interactive shell inside the VM |
| `airlock list` | Show all sandboxes |
| `airlock status [name]` | Show sandbox status, mounts, and network state |
| `airlock stop [name]` | Stop a sandbox |
| `airlock reset [name]` | Reset sandbox to its clean snapshot |
| `airlock destroy [name]` | Delete a sandbox and all its data |
| `airlock lock [name]` | Block all outbound network traffic (DNS still works) |
| `airlock unlock [name]` | Re-enable outbound network traffic |
| `airlock remove <mount> --sandbox <name>` | Unmount a project from a sandbox |
| `airlock config` | Show resolved configuration |
| `airlock profile` | List available security profiles |
| `airlock version` | Print version |

Commands that accept a `[name]` argument default to `airlock` if omitted.

### Sandbox creation flags

```bash
airlock sandbox ./my-project \
  --profile cautious \     # Security profile: strict, cautious, dev, trusted
  --runtime node \          # Override auto-detected runtime
  --docker \                # Allow Docker access inside the sandbox
  --ephemeral \             # Mark as ephemeral (metadata only)
  --ports 3000:9999 \       # Port range to forward
  --name my-sandbox         # Custom sandbox name
```

Runtime auto-detection checks for: `package.json` (node), `go.mod` (go), `Cargo.toml` (rust), `.python-version` / `requirements.txt` (python), `Dockerfile` (docker), `compose.yml` / `compose.yaml` (compose), `Makefile` (make), `*.sln` / `*.csproj` (dotnet).

GitHub URL formats: `gh:user/repo` or `https://github.com/user/repo` — the repo name becomes the sandbox name.

## Security profiles

Profiles encode security policies so you don't have to be an expert. The default is `cautious`.

| Profile | Host mounts | Network | Docker | Project dir | When to use |
|---------|------------|---------|--------|-------------|-------------|
| `strict` | None | Locked after setup | No | Read-only | Completely untrusted software |
| `cautious` | Read-only | Locked after setup | No | Read-only | Unknown software (default) |
| `dev` | Read-write | Open | Yes | Writable | Software you trust for development |
| `trusted` | Read-write | Open | Yes | Writable | Software you author or fully trust |

Network locking uses iptables inside the VM. `Lock` blocks all outbound connections except DNS. `Unlock` restores normal access. `LoadAfterSetup: true` (strict, cautious) means the network is locked immediately after the sandbox is created.

## Configuration

Create `airlock.toml` or `airlock.yaml` in your project directory. All fields are optional — defaults are used for anything you omit.

```toml
[vm]
cpu = 2
memory = "4GiB"
disk = "20GiB"
node_version = 22

[security]
profile = "cautious"        # strict, cautious, dev, trusted

[dev]
ports = "3000:9999"         # port range forwarded to localhost
command = "npm run dev"     # default run command

[runtime]
type = "node"               # override auto-detection: node, go, rust, python, docker, compose, make, dotnet
docker = false

[services]
compose = "./docker-compose.yml"   # Docker Compose file to start automatically

[[mounts]]
path = "./api"              # required: path relative to config file

[[mounts]]
path = "./shared"
writable = false            # default: true
inotify = true              # default: false; enables file-watch events (Lima ≥ 0.21)
```

Precedence: CLI flags > config file > built-in defaults.

YAML format (`airlock.yaml` or `airlock.yml`):

```yaml
vm:
  cpu: 2
  memory: "4GiB"
  disk: "20GiB"

security:
  profile: "cautious"

dev:
  ports: "3000:9999"

mounts:
  - path: "./shared"
    writable: false
```

### Config reference

| Section | Field | Type | Default | Description |
|---------|-------|------|---------|-------------|
| `vm` | `cpu` | int | `2` | Number of CPU cores |
| `vm` | `memory` | string | `"4GiB"` | VM memory allocation (supports KiB, MiB, GiB) |
| `vm` | `disk` | string | `"20GiB"` | VM disk size |
| `vm` | `node_version` | int | `22` | Node.js major version to install |
| `security` | `profile` | string | `"cautious"` | Security profile name |
| `dev` | `ports` | string | `"3000:9999"` | Port range to forward |
| `dev` | `command` | string | — | Default command to run |
| `runtime` | `type` | string | auto-detected | Override runtime type |
| `runtime` | `docker` | bool | `false` | Allow Docker in sandbox |
| `services` | `compose` | string | — | Path to Docker Compose file (must be relative) |
| `mounts[]` | `path` | string | — | Required. Relative path to mount |
| `mounts[]` | `writable` | bool | `true` | Whether mount is writable in VM |
| `mounts[]` | `inotify` | bool | `false` | Enable inotify file-watch events |

## Network control

```bash
airlock lock my-sandbox     # Block all outbound (DNS still works)
airlock unlock my-sandbox   # Re-enable outbound
```

Network policies are enforced per-sandbox via iptables inside the VM. Locking applies:

- DNS (UDP port 53) is always allowed
- Inbound established connections are allowed in `strict` and `cautious` profiles
- All other outbound traffic is blocked when locked

## Architecture

```
cmd/airlock/cli/         CLI entry point (Cobra commands, dependency injection)
internal/api/            Interface contracts (SandboxManager, Provider, NetworkController, etc.)
internal/sandbox/        Orchestrator — Create, Run, Stop, Destroy, Reset, List, Status
internal/vm/lima/        Lima VM provider (limactl wrapper, config generation, snapshots)
internal/network/        Network policy controller (iptables via limactl)
internal/mount/          Mount registry (JSON-backed persistence)
internal/detect/         Runtime auto-detection (Node, Go, Rust, Python, Docker, etc.)
internal/profile/        Security profile registry (strict, cautious, dev, trusted)
internal/config/         TOML/YAML config loading, validation, defaults
internal/sysutil/        Host resource detection (CPU, memory, disk)
test/integration/        End-to-end tests with fake limactl
```

All packages communicate through interfaces defined in `internal/api/`. The CLI never imports concrete types in command handlers — dependencies are injected through the `Dependencies` struct with interface fields only (Dependency Inversion Principle).

Each sandbox gets its own Lima VM (`airlock-<name>`). State is persisted in `~/.airlock/sandboxes.json` and `~/.airlock/mounts.json`. A clean snapshot is taken during `setup` and `reset` restores the VM to that baseline.

### Data flow

```
airlock sandbox ./project
  → CLI validates args, resolves config
  → Manager.Create(spec)
    → detect runtime → resolve profile → validate resources
    → Provider.Create (limactl create + start)
    → NetworkController.ApplyPolicy (iptables rules)
    → MountManager.Register (JSON persistence)
  → returns SandboxInfo
```

## Development

```bash
make build          # Build the binary
make test           # Run all tests
make test-unit      # Run unit tests only
make test-integration # Run integration tests only
make vet            # Run go vet
make fmt            # Check formatting
make lint           # Run vet + fmt check
make install        # Build and install to GOPATH/bin
```

Requires Go 1.23+. Integration tests use a fake `limactl` shell script — no Lima installation needed for CI.

## Files

| Path | Purpose |
|------|---------|
| `~/.airlock/sandboxes.json` | Sandbox state registry |
| `~/.airlock/mounts.json` | Mount registry |
| `~/.lima/airlock-<name>/` | Lima VM instance directory |
| `./airlock.toml` | Per-project config (optional) |

## License

[MIT](LICENSE)