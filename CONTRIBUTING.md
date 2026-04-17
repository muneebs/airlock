# Contributing to Airlock

Thank you for your interest in contributing. This document covers the practical steps for getting a change merged.

## Prerequisites

- Go 1.24
- Lima (for manual testing on macOS)
- `make` (build tasks are in the Makefile)

## Development setup

```bash
git clone https://github.com/muneebs/airlock
cd airlock
make install
```

This builds and installs the `airlock` binary to `$GOPATH/bin`.

## Running tests

```bash
make test            # All tests (unit + integration)
make test-unit        # Unit tests only (internal/...)
make test-integration # Integration tests (test/integration/...)
```

Integration tests use a fake `limactl` shell script — no Lima installation required for CI.

## Code style

- Run `make lint` before pushing. This runs `go vet` and `gofmt` checks.
- Follow standard Go conventions: `gofmt`, `go vet`, effective Go.
- No comments on code unless they explain *why*, not *what*.
- Exported functions and types must have doc comments.

## Design principles

All changes must satisfy the principles in [PRINCIPLES.md](PRINCIPLES.md). Key ones:

1. **Packages are boundaries.** Cross-package dependencies go through interfaces, not concrete types.
2. **Dependency Inversion.** The CLI never imports concrete types in handlers. Low-level packages implement interfaces from `internal/api/`.
3. **No `if concreteType` checks.** Use interfaces and composition, not type switches.
4. **Tests as documentation.** Every exported function should have a test that shows how to use it.
5. **Security matters.** Network policy, mount handling, credential logic, and privilege escalation paths get line-by-line human review regardless of origin.

## Pull request process

1. Create a feature branch from `main`.
2. Make your changes with tests.
3. Run `make lint && make test` — both must pass.
4. Open a PR against `main`.

### PR description must include

- Summary of what changed and why
- Which existing tests cover the change, or what new tests you added
- **AI use disclosure** (see below)

### AI use disclosure

Per Principle 6 in PRINCIPLES.md, every PR must state:

- Whether AI tools were used (e.g., Copilot, ChatGPT, Claude)
- Which tools and to what extent (e.g., "AI-generated first draft, human-reviewed and modified" or "AI-assisted autocomplete only")
- Omission is not acceptable. Overstatement is also not acceptable.

Security-sensitive code (network policy, mount handling, credential copying, privilege escalation) must be human-reviewed line-by-line regardless of its origin.

## Package structure

```
cmd/airlock/cli/         CLI commands and dependency injection
internal/api/            Interface contracts
internal/sandbox/        Orchestrator (Create, Run, Stop, Destroy, Reset, List, Status)
internal/vm/lima/        Lima VM provider
internal/network/        Network policy controller (iptables)
internal/mount/          Mount registry (JSON persistence)
internal/detect/         Runtime auto-detection
internal/profile/        Security profile registry
internal/config/         Config loading (TOML/YAML)
internal/sysutil/        Host resource detection
test/integration/        End-to-end tests
```

When adding a new package, add it to this list and ensure it has a single responsibility. If the name needs "and" in it, split it.

## Adding new features

### New runtime detector

Implement `detect.RuntimeDetector` and register it in `detect.NewCompositeDetector()`:

```go
type RuntimeDetector interface {
    Detect(ctx context.Context, dir string) (api.Runtime, error)
}
```

### New security profile

Call `profile.Registry.Register()` with an `api.Profile`:

```go
p := api.Profile{
    Name:        "custom",
    Description: "Custom profile for ...",
    Network:     api.NetworkPolicy{...},
    Mount:       api.MountPolicy{...},
    Docker:      api.DockerPolicy{...},
    Filesystem:  api.FilesystemPolicy{...},
}
```

### New VM backend

Implement `api.Provider`, `api.Provisioner`, and `api.ShellProvider`, then wire it in `cmd/airlock/cli/cli.go`.

## Report issues

Open a GitHub issue with:

- What you expected
- What happened instead
- Your macOS version, Lima version, and `airlock version` output
- Steps to reproduce