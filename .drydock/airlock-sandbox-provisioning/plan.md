# Plan: airlock-sandbox-provisioning

- Ticket: `airlock-sandbox-provisioning`
- Repo: `/Users/muneebsamuels/dev/sandbox` (module `github.com/muneebs/airlock`)
- Stage: 2 — Plan
- Branch: `fix/airlock-sandbox-provisioning` (off `main`)
- Spec: `.drydock/airlock-sandbox-provisioning/spec.md` (7 AC, risk NORMAL)

---

## Root cause (re-verified against source this pass)

- `newSandboxCmd` (`cmd/airlock/cli/cli.go:353/357`) calls `deps.Manager.Create`
  only. `Create → CreateWithProgress → CreateWithOptions`
  (`internal/sandbox/create.go:17,25,30`) validates, resolves runtime/profile,
  boots the VM, (clones remote), applies network policy, and registers the mount
  — **it never invokes any Provisioner method.** No `Provisioner` is even a
  dependency of `sandbox.Manager` (`internal/sandbox/sandbox.go:37-49`); the
  provisioner lives only in the CLI `Dependencies` (`cli.go:29`).
- `newSetupCmd` provisions in the **CLI layer**: it calls `CreateWithOptions`
  with `SkipNetworkPolicy:true` (`cli.go:231-236`), then iterates
  `deps.Provisioner.ProvisionSteps(name, provisionOpts)` (`cli.go:245`), then
  `ApplyNetworkProfile`, then `SnapshotClean`. The `init` wizard path does the
  same (`cli.go:884-946`).
- Baseline steps that make a VM usable live in
  `internal/vm/lima/provision.go:59-68`: system packages, **create `airlock`
  user** (`:61`), passwordless sudo, prepare `/home/airlock` (`:68`). Node steps
  at `:71-78`, gated on `opts.InstallNode` (or an npm-requiring AI tool).
- The per-ticket mount lands at `/home/airlock/projects/<name>`
  (`internal/mount/mount.go:69`, and `resolveResources` at
  `internal/sandbox/sandbox.go:159-166` puts the same `GuestPath` into
  `vmSpec.Mounts`). With no `airlock` user, uid 501 (`muneebsamuels`) cannot
  traverse a `/home/airlock`-rooted mount, and `ExecAsUser(..., "airlock", ...)`
  (`internal/sandbox/run.go:89` → `internal/vm/lima/provider.go:209`
  `sudo -u airlock`) fails with `sudo: unknown user airlock`.

**Search-first:** the reuse target is the existing
`Provisioner.ProvisionSteps` / `ProvisionVM` machinery
(`internal/vm/lima/provision.go:15,39`). No parallel provisioning path is
invented. `CreateWithOptions` is already on the `SandboxManager` interface
(`internal/api/sandbox.go:61`), so the CLI already has the entry point.

---

## Architectural decision — Approach (a): provision the per-ticket VM with the SAME `ProvisionSteps`

**Chosen: (a)** run the identical `Provisioner.ProvisionSteps` sequence for the
per-ticket VM, invoked from inside the sandbox `Manager` create flow (not a
second copy in the CLI). **Rejected: (b)** clone/reuse the base `airlock` VM.

`#PATH_DECISION`
- **Alternatives considered:**
  - **(a) Provision the per-ticket VM** with the shared step builder.
  - **(b) Reuse/clone the already-provisioned base VM** (snapshot-clone or run
    the sandbox as an overlay/namespace on the shared `airlock` VM).
- **Why (a):**
  - **Correctness by construction.** The per-ticket VM runs the *exact* steps
    the base VM runs (same `ProvisionSteps` builder), so it is usable the same
    way. `airlock` user, sudoers, `/home/airlock`, and Node are produced by
    identical code — there is no second implementation to keep correct.
  - **Isolation is the product invariant.** `sandbox.Manager` is documented as
    "each sandbox gets its own VM with no shared state"
    (`internal/api/sandbox.go` SandboxManager doc). (b) inherits the base VM's
    identity/mounts/network and breaks per-ticket network policy + per-ticket
    mount at `/home/airlock/projects/<name>`; you would still have to re-apply
    mount and network per ticket, so (b) is *more* work, not less.
  - **Mechanism (b) isn't supported here.** `SnapshotClean`/`RestoreClean`
    (`internal/vm/lima/*`) are same-VM save/restore, not cross-name clone. There
    is no clone-into-new-name primitive; building one is a larger, riskier change
    than the diagnosed defect warrants.
- **Trade-off accepted:** (a) pays the apt + Node install cost on every
  per-ticket sandbox (minutes). That is acceptable — a per-ticket dev VM that
  can actually run verification is the point; speed is a follow-up (could later
  cache/snapshot per-runtime base images, explicitly out of scope here).

### Where provisioning is invoked — inside `Manager.CreateWithOptions`, not the CLI

`#PATH_DECISION`
- **Alternative:** mirror `setup` and provision in `newSandboxCmd` after
  `Create` returns (CLI layer).
- **Rejected because of ordering:** for a **remote** source,
  `cloneRemoteSource` runs `ExecAsUser(ctx, name, "airlock", git clone ...)`
  *inside* `CreateWithOptions` (`create.go:101-113,183`) — that clone needs the
  `airlock` user to already exist. CLI-after-`Create` provisioning would run too
  late for remote sources. Provisioning must sit **after boot but before clone
  and before network policy**, which is inside `CreateWithOptions`.
- **Chosen:** inject a `Provisioner` into `sandbox.Manager` and run the shared
  steps inside `CreateWithOptions`, gated by a new `CreateOptions.Provision`
  flag. `setup`/`init` leave the flag unset and keep their current CLI-layer
  per-step provisioning untouched → **AC6 preserved** (no behavior change, and
  `setup` keeps its per-step TUI which `Create`'s coarse progress callback
  cannot reproduce). Divergence is structurally prevented: both paths call the
  one `ProvisionSteps` builder; only the *invocation site and options* differ,
  and the option mapping is a single unit-tested helper.

### Ordering (load-bearing)

Inside `CreateWithOptions`, the sequence becomes:

1. validate → resolve runtime/profile → register state
2. `createAndStartVM` (boot; for **local** sources the virtiofs mount at
   `/home/airlock/projects/<name>` is present from `vmSpec.Mounts`)
3. **provision (NEW, if `opts.Provision`)** — baseline creates `airlock` user
   and `/home/airlock`; Node steps if runtime is node
4. clone remote source (now the `airlock` user exists)
5. apply network policy / lock (now `iptables` is installed and Node was
   downloaded while egress was still open)
6. register mount (metadata)

The baseline "Preparing airlock home" step (`provision.go:68`) already uses
`find -xdev ... -path /home/airlock/projects -prune` and chowns the
`projects` dir itself (not its contents), so running it **with the mount already
present** correctly gives `airlock` ownership/traversal of the mount point
without EPERM-ing into virtiofs. This is exactly why provisioning-after-boot is
safe and why the mount becomes reachable (AC4).

---

## Files to touch

| File | Change |
|---|---|
| `internal/api/sandbox.go` | Add `Provision bool` to `CreateOptions` (doc: run baseline+runtime provisioning inside Create; ordered before clone/network). |
| `internal/sandbox/sandbox.go` | Add `provisioner api.Provisioner` field to `Manager`; add param to `NewManager`; add pure helper `provisionOptionsForRuntime(rt api.RuntimeType) api.ProvisionOptions` (node ⇒ `InstallNode:true`, else baseline-only). |
| `internal/sandbox/create.go` | In `CreateWithOptions`, after `createAndStartVM` and **before** `cloneRemoteSource`/`applyNetworkPolicy`: if `opts.Provision`, build opts via `provisionOptionsForRuntime(runtimeType)` and run `m.provisioner.ProvisionVM(ctx, spec.Name, ...)` with `report(...)` stages and the same errored-state rollback used by the neighboring steps. |
| `cmd/airlock/cli/cli.go` (`newSandboxCmd`, ~353/357) | Call `deps.Manager.CreateWithOptions(ctx, spec, api.CreateOptions{Progress: ..., Provision: true})` instead of `Create`. Keep spinner + `--json` branches. No change to `newSetupCmd` / `init` wizard. |
| `internal/bootstrap/bootstrap.go` (~64) | Pass `limaProvider` as the new provisioner arg to `NewManager` (it already implements `api.Provisioner` and is passed as provider+resetter). |
| `test/integration/harness_test.go` (~127) + `internal/sandbox/sandbox_test.go` (5 call sites) | Update `NewManager(...)` calls for the new param (pass a fake/real provisioner). |

No changes to `internal/vm/lima/provision.go` (reused as-is), `run.go`,
`provider.go`, `mount.go`, or `profile.go`.

---

## AC → change map (at a glance)

| AC | Delivered by |
|---|---|
| **AC1** baseline provisioning + `airlock` user on sandbox path | `create.go` runs `ProvisionVM` inside `CreateWithOptions` when `Provision:true`; `newSandboxCmd` sets it. Baseline steps unchanged (`provision.go:59-68`). |
| **AC2** `run -- true`/`whoami` no longer `unknown user airlock` | Consequence of AC1 (user now exists before `ExecAsUser`). |
| **AC3** `--runtime node` ⇒ node/npm on PATH | `provisionOptionsForRuntime(RuntimeNode) → InstallNode:true`; derived from the **resolved** `runtimeType` inside Create, so explicit `--runtime node` *and* auto-detected node worktrees both provision Node. |
| **AC4** mount r/w by run-user `#EXPORT_CRITICAL` | Ordering: provision (creates `airlock`, chowns `/home/airlock/projects` via `-xdev` prune) runs after boot with the mount present, before run. See test strategy for how this is asserted vs. live-verified. |
| **AC5** end-to-end verification cmd runs | Emergent from AC1+AC3+AC4 (real user + node + reachable rw mount). |
| **AC6** `setup`/base-VM unchanged `#EXPORT_CRITICAL` | `Provision` defaults false; `newSetupCmd`/`init` untouched and still provision in the CLI layer. Regression test asserts Create does **not** provision when `Provision` is unset. |
| **AC7** profile semantics preserved | No change to `resolveProfile`/`applyNetworkPolicy`/`resolveResources`; provisioning does not read or alter `prof.Mount`/`prof.Network`. Provision is ordered before network apply exactly as `setup` already does, so lock timing is unchanged per profile. |

---

## Test strategy

Unit-first, mirroring existing table tests
(`internal/vm/lima/provision_test.go`, `internal/sandbox/sandbox_test.go`). The
spec (lines 88-92) explicitly permits asserting the emitted step/command
sequence where a full boot is impractical.

1. **`provisionOptionsForRuntime` table test** (`internal/sandbox`): `node ⇒
   InstallNode true`; `go`/`rust`/`python`/`unknown` ⇒ `InstallNode false`,
   baseline only. Directly covers **AC3**'s "requests Node provisioning when the
   resolved runtime is node".
2. **Sandbox-path provisioning test** (`internal/sandbox/sandbox_test.go`): add a
   `fakeProvisioner` recording `ProvisionVM` calls (name + opts) and, via the
   existing `fakeProvider`, the ordered command/ExecAsUser calls. Assert that
   `CreateWithOptions(..., {Provision:true})` with a node runtime:
   - calls the provisioner exactly once with `InstallNode:true`;
   - the provisioner runs **before** any `ExecAsUser` clone (remote-source case)
     and **before** `applyNetworkPolicy` (ordering guard — covers **AC1**, and
     the `#PLAN_UNCERTAINTY` U2 below).
3. **AC4 `#EXPORT_CRITICAL`** — two layers:
   - *Unit (stand-in):* assert the emitted baseline sequence for the sandbox
     path contains "Creating airlock user" and "Preparing airlock home" (the
     `-xdev`-prune chown of `/home/airlock/projects`), i.e. the ownership that
     makes the mount traversable is requested. Reuse the step-label inspection
     pattern from `provision_test.go`.
   - *Live (QAS, must not be deferred):* on a booted dev-profile sandbox,
     `airlock run <s> -- ls /home/airlock/projects/<s>` lists the worktree and a
     write-then-readback under that path via `airlock run` succeeds. This is the
     only real proof of the virtiofs uid mapping (U1).
4. **AC6 `#EXPORT_CRITICAL` regression:** assert `CreateWithOptions(..., {})`
   (Provision unset, the `setup` shape with `SkipNetworkPolicy:true`) makes **no**
   provisioner call. Existing `internal/vm/lima` provision/snapshot tests remain
   green unchanged (proves the shared builder is untouched).
5. **Gates:** `go build ./...`, `go test ./...`, `go vet ./...` green (DoD).
   Evidence captured per `drydock-evidence` including before/after
   `run -- node --version` (or the step-sequence assertions standing in).

---

## `#PLAN_UNCERTAINTY`

- **U1 (load-bearing) — virtiofs uid mapping for AC4.** Chowning
  `/home/airlock/projects` to `airlock` makes the *mount point* traversable, but
  whether the `airlock` guest uid gets **read/write on the mount contents**
  depends on how Lima virtiofs maps ownership (guest uid vs. host uid 501).
  Provisioning is necessary; it may not be sufficient if virtiofs pins contents
  to the host user. **Validate:** QAS live write-then-readback under
  `/home/airlock/projects/<name>` as the run-user (AC4). If it fails, the follow
  -up is a mount-option / uid-map change in `internal/vm/lima` mount config —
  flagged now so it is not discovered at Stage 4.
- **U2 — provision vs. network lock for cautious/strict per-ticket sandboxes.**
  Node install needs open egress; a locking profile must not lock before
  provisioning. The plan orders provision before `applyNetworkPolicy` inside
  Create (parity with `setup`). **Validate:** ordering assertion in test #2.
- **U3 — Node version for per-ticket sandboxes.** Manager has no config, so
  `provisionOptionsForRuntime` leaves `NodeVersion:0`, which `ProvisionSteps`
  defaults to 22 (`provision.go:41-43`). Acceptable per scope (Node-only, no
  parity mandate). Not a blocker; noted so QAS doesn't flag "wrong node version"
  as a regression.

## Historian

Considered per `drydock-workflow`. Recent churn in this area (#9 isolation, #11
remote clone, #12 mount-type fallback) touches **mount mechanism**, not the
provisioning-wiring gap this ticket fixes; the defect is already root-caused
in-code in the spec. Judged low-value to block on `@drydock-historian`;
proceeding. U1 is the one place mount history could matter — if AC4 live-fails,
pull `history.md` on `internal/vm/lima` mount config before choosing the uid-map
fix.
