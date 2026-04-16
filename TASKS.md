# Airlock — Task Tracker

## Completed

### [DONE] PR #1 — Foundation (merged to main)
- [x] PRINCIPLES.md with 6 core rules
- [x] Go project scaffold with 8 packages and full test suite
- [x] `internal/api/` — SandboxManager, Provider, NetworkController, MountManager, RuntimeDetector interfaces
- [x] `internal/config/` — TOML + YAML loading, validation, defaults, round-trip serialization (16 tests)
- [x] `internal/profile/` — 4 security profiles + extensible registry (9 tests)
- [x] `internal/detect/` — 8 runtime detectors with priority ordering, errors.As, fileExists returning (bool,error) (20 tests)
- [x] `internal/mount/` — JSON-backed mount registry with persistence, sanitizeName (8 tests)
- [x] `internal/network/` — injectable CommandRunner/OutputRunner, atomic iptables-restore, CurrentPolicy() (11 tests)
- [x] `internal/sysutil/` — OS-specific memory detection (darwin/linux/others), parseMemoryString (int64,error), CheckResources (9 tests)
- [x] `cmd/airlock/cli/` — Cobra CLI skeleton (12 commands, all stubs except version)
- [x] Security hardening in `bin/airlock` (path traversal, credential exposure, injection)

### [DONE] PR #2 — Lima VM Provider (on branch, pending merge)
- [x] `internal/vm/lima/config.go` — GenerateConfig from VMSpec, parsePortRange (15 tests)
- [x] `internal/vm/lima/provider.go` — LimaProvider implementing api.Provider, limactl operations
- [x] `internal/vm/lima/snapshot.go` — SnapshotClean/RestoreClean, ProvisionVM, copyDir (3 tests)
- [x] Compile-time interface check for Provider

### [DONE] PR #3 — Sandbox Orchestrator + Lima Security Hardening
- [x] `internal/sandbox/sandbox.go` — Manager implementing api.SandboxManager, JSON-backed state persistence, Resetter/ResourceChecker interfaces, derefInt helper, compile-time interface check
- [x] `internal/sandbox/create.go` — Create workflow: validate → resources → detect runtime → resolve profile → provision VM → apply network policy → register mounts; atomic name reservation (TOCTOU fix); orphaned VM cleanup on Start failure
- [x] `internal/sandbox/run.go` — Run workflow (start VM, exec command as user) + Start workflow; re-read info under lock before state mutation
- [x] `internal/sandbox/stop.go` — Stop workflow: gracefully stop VM; re-read info under lock; surface m.put errors
- [x] `internal/sandbox/delete.go` — Destroy workflow: check running state → stop → delete VM → cleanup all mounts → remove state; handle IsRunning errors
- [x] `internal/sandbox/reset.go` — Reset workflow: check snapshot → stop → restore clean → restart; re-read info under lock; nil guard for concurrent deletion; surface m.put errors
- [x] `internal/sandbox/list.go` — List + Status with live VM state reconciliation; StateErrored preserved; state mutation inside lock scope
- [x] `internal/sandbox/sandbox_test.go` — 38 tests with faked dependencies covering all workflows, error paths, persistence, edge cases, concurrent duplicate creation
- [x] Lima config file permissions 0644 → 0600 (owner-only)
- [x] Sensitive host mount path blocklist (/etc, /root, /proc, /sys, /dev, /home, /var/run/docker.sock, etc.)
- [x] Provision command whitelist regex (safeProvisionCmd) replacing blacklist — only allows alphanumerics, space, hyphen, underscore, dot, slash, colon, equals, tilde, at, plus, comma, hash
- [x] shellEscape wraps each argument in single quotes to preserve argument boundaries
- [x] Snapshot permission masking via safeFilePerm() — strips SUID, SGID, world-write bits (0755 mask)

### [DONE] Security Fixes (applied to bin/airlock)
- [x] Path traversal in mount configs
- [x] Automatic credential exposure in non-TTY sessions
- [x] Shell injection via ANTHROPIC_API_KEY
- [x] SI vs IEC unit confusion
- [x] `fileExists` silently swallowing errors
- [x] `parseMemoryString` returning 0 for malformed input
- [x] One-by-one iptables rule mutation
- [x] `LockAfterSetup` correctly scoped as orchestrator-level directive

## Remaining

### [DONE] PR #4 — Wire CLI to Real Implementations
- [x] `cmd/airlock/cli/cli.go` — All 15 Cobra commands wired through `Dependencies` struct (interfaces only)
- [x] `airlock setup` → Manager.Create + Provisioner.ProvisionVM + Provisioner.SnapshotClean
- [x] `airlock sandbox` → Manager.Create (flags: --profile, --runtime, --docker, --ephemeral, --ports, --name)
- [x] `airlock run` → Manager.Run
- [x] `airlock shell` → ShellProvider.Shell (with TTY detection)
- [x] `airlock list` → Manager.List (with --json flag)
- [x] `airlock remove` → MountManager.Unregister (with --sandbox flag)
- [x] `airlock status` → Manager.Status + MountManager.List + NetworkController.IsLocked
- [x] `airlock stop` → Manager.Stop
- [x] `airlock reset` → Manager.Reset
- [x] `airlock destroy` → Manager.Destroy
- [x] `airlock lock` → NetworkController.Lock
- [x] `airlock unlock` → NetworkController.Unlock
- [x] `airlock config` → config.Load + config.WriteTOML/WriteYAML
- [x] `airlock profile` → profile.Registry.List/Get
- [x] Handle flags: --profile, --runtime, --docker, --ephemeral, --ports, --name, --node-version, --json, --format
- [x] TTY detection for shell command
- [x] Added `Run` and `Reset` to `api.SandboxManager` interface (eliminates type assertions)
- [x] Added `api.Provisioner` and `api.ShellProvider` interfaces (ISP)
- [x] Rewrote `Dependencies` struct with only interface fields (no concrete types)
- [x] `mount.JSONStore.Apply()` method added to satisfy `api.MountManager`
- [x] Wired production `limactlRunExec`/`limactlOutputExec` to `exec.CommandContext`
- [x] Single shared `LimaController` instance (no duplicate)
- [x] Fixed `TestCheckResourcesForSpec` (pre-existing test bug)
- [x] Compile-time interface checks for `api.Provisioner` and `api.ShellProvider`
- [x] Systematic review against all past security issues — no regressions

### [ ] PR #5 — Integration Tests
- [ ] `test/integration/create_test.go` — End-to-end create + verify VM exists
- [ ] `test/integration/run_test.go` — End-to-end run command inside sandbox
- [ ] `test/integration/network_test.go` — Verify firewall rules applied correctly
- [ ] `test/integration/snapshot_test.go` — Verify reset restores clean state
- [ ] `test/integration/detect_test.go` — Verify runtime auto-detection in real projects
- [ ] CI pipeline configuration (GitHub Actions?)

### [ ] PR #6 — Documentation & Polish
- [ ] README.md — installation, quickstart, architecture overview
- [ ] Configuration reference (TOML/YAML options)
- [ ] Security profiles documentation
- [ ] CONTRIBUTING.md
- [ ] goreleaser or Makefile for binary distribution

## Design Decisions (for reference)

| Decision | Rationale |
|---|---|
| Per-sandbox VM (`airlock-<name>`) | Isolation; original script used single shared VM |
| `cautious` default profile | Safe defaults for non-experts |
| `LockAfterSetup` is orchestrator-level | Not consumed by ApplyPolicy (would break Unlock) |
| `errors.As` over concrete asserts | Properly handles wrapped ErrNotDetected |
| Writable mounts default to false | Security-first; read-only by default |
| iptables via `iptables-restore` | Atomic; one-by-one leaves VM exposed on failure |
| Non-TTY skips credential copying | Prevents silent credential exposure |
| `compose.yml` / `compose.yaml` | Modern Docker Compose (no `docker-` prefix) |
| `sysctl hw.memsize` on macOS | `/proc/meminfo` is Linux-only |
| Atomic name reservation in Create | TOCTOU: check + put under same lock prevents duplicate sandboxes |
| Re-read info under lock before mutation | Stale pointer races in Stop/Reset/Run/Start/List |
| `safeProvisionCmd` whitelist over blacklist | Blacklist misses newline, quotes, parens, redirection, backslash |
| `shellEscape` wraps in single quotes | Preserves argument boundaries for spaces in ExecAsUser |
| `safeFilePerm` 0755 mask in snapshots | Strips SUID/SGID/world-write to prevent privilege escalation |
| Delete VM on Start failure | Prevents orphaned VMs when Create succeeds but Start fails |
| `IsRunning` errors are fatal in Delete | Prevents deleting a running VM when state is unknown |
| `Resetter` as separate interface | ISP: snapshot methods don't belong on api.Provider |