# Spec: airlock-sandbox-provisioning

- Ticket: `airlock-sandbox-provisioning`
- Repo: `/Users/muneebsamuels/dev/sandbox` (module `github.com/muneebs/airlock`)
- Stage: 1 — Requirements
- Risk: **NORMAL** (reasoning below)
- State: Ready for Plan
- Origin: confirmed field diagnosis, reproduced and root-caused in-code.

---

## Problem statement

A `risk:high` drydock ticket provisions a per-ticket sandbox with:

```
airlock sandbox <worktree> --profile dev --runtime node --name drydock-<ticket>
```

The resulting sandbox comes up misprovisioned and cannot run Stage-3/4
verification. Two distinct defects were reproduced and root-caused against the
source in this repo.

### Defect 1 — the per-ticket sandbox is created but never provisioned

The `setup` and `sandbox` commands take two different code paths:

- `newSetupCmd` (`cmd/airlock/cli/cli.go:147`) creates+boots the VM via
  `Manager.CreateWithOptions(...)` **and then runs
  `deps.Provisioner.ProvisionSteps(name, provisionOpts)`** (cli.go:245) before
  applying network policy and snapshotting.
- `newSandboxCmd` (`cmd/airlock/cli/cli.go:286`) calls only
  `deps.Manager.Create(ctx, spec)` (cli.go:353/357). `Manager.Create` /
  `CreateWithOptions` (`internal/sandbox/create.go:17`, `:30`) validates,
  resolves runtime+profile, creates+boots the VM, applies network policy, and
  registers the mount — **it never calls `ProvisionSteps` / `ProvisionVM`**.

The baseline provisioning that the sandbox path skips
(`internal/vm/lima/provision.go:59`) is exactly what makes a VM usable:

- `"Creating airlock user"` — `id airlock || useradd -m -s /bin/bash airlock`
  (provision.go:61). Without it there is **no `airlock` guest user**.
- Node.js/npm/pnpm install steps (provision.go:71-78), gated on
  `opts.InstallNode`. Without provisioning, **`node`/`npm` are never installed**.

Consequences confirmed in code:

- `airlock run <name> -- <cmd>` (`newRunCmd`, cli.go:388) calls
  `Manager.Run` (`internal/sandbox/run.go:42`), which executes
  `m.provider.ExecAsUser(ctx, name, "airlock", command)` (run.go:89). `ExecAsUser`
  (`internal/vm/lima/provider.go:209`) runs `sudo -u airlock bash --login -c ...`.
  With no `airlock` user this fails with
  `sudo: unknown user airlock: sudo: error initializing audit plugin sudoers_audit`.
- `--runtime node` on `sandbox` only sets `spec.Runtime`, which feeds
  `resolveRuntime` (create.go:264) as **metadata**. It is not mapped to any
  `ProvisionOptions.InstallNode`, and no provisioning runs regardless — so the
  runtime flag never installs a runtime.

The base `airlock` VM works because `setup` ran the provisioner; the per-ticket
VM does not, so it is a bare Ubuntu image with only the Lima default user
(`muneebsamuels`, uid 501).

### Defect 2 — the worktree mount is unreachable by the only usable guest user

The worktree is mounted (virtiofs, rw) at `/home/airlock/projects/<name>`
(`internal/mount/mount.go:69` sets `VMPath = /home/airlock/projects/<name>`;
`internal/sandbox/create.go:182` uses the same guest path for clones). That path
lives under `/home/airlock`.

Because Defect 1 skips provisioning, the `airlock` user and its home
(`useradd -m` + the `"Preparing airlock home"` chown, provision.go:68) are never
created. The only real guest user is the Lima default `muneebsamuels` (uid 501),
which cannot traverse/read a `/home/airlock`-rooted mount. Net: the worktree
files are present but unreadable/unwritable by the user any command actually runs
as, so verification cannot run.

Defect 2 is coupled to Defect 1 (no `airlock` user ⇒ nothing owns
`/home/airlock`), but is called out separately because the fix must guarantee an
outcome — the mount must be readable/writable by whatever user `airlock run`
executes as — not merely "provisioning ran".

---

## Acceptance Criteria

Each AC is verified against a per-ticket sandbox created with
`airlock sandbox <worktree> --profile dev --runtime node --name <sandbox>`
(the drydock invocation), unless stated otherwise. Where full VM boot is
impractical in unit tests, the AC is satisfied by asserting the command/step
sequence the sandbox path emits (the provisioning steps are pure, inspectable
`[]api.ProvisionStep` values — see `provision.go:39` and existing tests in
`internal/vm/lima/snapshot_test.go:220+`).

**AC1.** A per-ticket sandbox created via the `sandbox` command runs the same
baseline provisioning the `setup`/base-VM path runs: system packages, **create
`airlock` user**, passwordless sudo, and prepare `/home/airlock`. After
creation, an `airlock` guest user exists in the sandbox VM.

**AC2.** `airlock run <sandbox> -- true` (and `-- whoami`) succeeds — i.e.
`ExecAsUser(..., "airlock", ...)` no longer fails with
`sudo: unknown user airlock`. The command executes as a real, existing user.

**AC3.** A per-ticket sandbox created with `--runtime node` has `node` and `npm`
on `PATH` for the user `airlock run` executes as:
`airlock run <sandbox> -- node --version` and `-- npm --version` both exit 0 and
print a version. (Equivalently: the sandbox path requests Node provisioning when
the resolved runtime is `node`.)

**AC4.** The worktree mount at `/home/airlock/projects/<sandbox>` is
**readable and writable** by the user `airlock run` executes as:
`airlock run <sandbox> -- ls /home/airlock/projects/<sandbox>` lists the worktree
contents, and writing then reading back a file under that path via
`airlock run` succeeds. #EXPORT_CRITICAL

**AC5.** `airlock run <sandbox> -- <verification cmd>` succeeds end-to-end for the
provisioned Node runtime against the mounted worktree (representative:
`go build ./...` for a Go worktree, or `npm ci`/`node <script>` for a Node
worktree) — demonstrating Stage-3/4 verification can actually run inside a
per-ticket sandbox.

**AC6.** The base-VM (`setup`) provisioning path is unchanged in behavior: the
shared `airlock` VM still provisions node/bun/docker and the `airlock` user as
before. No regression to `setup`, `init`, `run`, or snapshot flows. #EXPORT_CRITICAL

**AC7.** Profile semantics are preserved. Under `--profile dev` the mount is
read-write (`profile.go` `dev`: `Mount.Writable = true`) and network open; the
provisioning fix must not silently widen or narrow the resolved profile's
network/mount/Docker policy for any profile.

### Out of scope

- Redesigning the per-ticket sandbox to run as a namespace/overlay on the shared
  base VM vs. provisioning its own VM. This spec fixes the *misprovisioning*
  outcome and is intentionally design-neutral; the architect chooses the
  mechanism (provision the per-ticket VM, or reuse the base VM) so long as the
  ACs hold.
- AI-tool installation (`--ai-tool`) into per-ticket sandboxes.
- Changes to network-locking / iptables behavior beyond preserving AC7.
- Snapshotting per-ticket sandboxes (`SnapshotClean`).
- Bun/Docker provisioning parity for per-ticket sandboxes (only Node is required
  by the diagnosis; broader parity is a follow-up).

---

## Definition of Done

- [ ] All ACs above satisfied; #EXPORT_CRITICAL ACs (AC4, AC6) explicitly
      verified by QAS and not deferred.
- [ ] Unit tests cover the sandbox provisioning path: that creating a sandbox
      emits the baseline provisioning (airlock user) and, for a `node` runtime,
      the Node install steps — mirroring existing table tests in
      `internal/vm/lima/snapshot_test.go` and `internal/sandbox/sandbox_test.go`.
- [ ] Regression test asserting `setup`/base-VM provisioning is unchanged (AC6).
- [ ] `go build ./...` green.
- [ ] `go test ./...` green.
- [ ] `go vet ./...` / repo linter green.
- [ ] Evidence captured per `drydock-evidence`: build/test/lint output, plus the
      before/after command sequence proving `airlock run <sandbox> -- node
      --version` and the mount read/write succeed (or the step-sequence
      assertions standing in for a live boot).
- [ ] Code review complete.

---

## Risk level: NORMAL (not high) — reasoning

This ticket modifies the airlock/sandbox tooling itself. It is verified by
`go build ./...` and `go test ./...` — static compilation and unit tests over
trusted, first-party code, with **no execution of untrusted input**.

Marking this `risk:high` would route verification through a per-ticket airlock
sandbox — the very component this ticket repairs. That is a bootstrap deadlock:
the sandbox cannot be trusted to verify its own fix while broken. Therefore risk
is deliberately set to **NORMAL** and verification runs on the host toolchain
(`go build`/`go test`). This reasoning is recorded so QAS does not escalate the
ticket back to high and re-introduce the deadlock.

---

## Key source references

- `cmd/airlock/cli/cli.go:147` — `newSetupCmd` (base VM: Create **+** ProvisionSteps)
- `cmd/airlock/cli/cli.go:286` — `newSandboxCmd` (per-ticket: Create only, no ProvisionSteps)
- `internal/sandbox/create.go:30` — `CreateWithOptions` (no provisioning call)
- `internal/sandbox/run.go:89` — `ExecAsUser(..., "airlock", ...)`
- `internal/vm/lima/provision.go:39` / `:59-68` — `ProvisionSteps`, baseline (airlock user, home)
- `internal/vm/lima/provision.go:71-78` — Node install steps
- `internal/vm/lima/provider.go:209` — `ExecAsUser` → `sudo -u airlock`
- `internal/mount/mount.go:69` — `VMPath = /home/airlock/projects/<name>`
- `internal/profile/profile.go:120` — `dev` profile (writable mount, open network)
