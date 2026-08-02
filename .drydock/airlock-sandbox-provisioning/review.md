# Stage 6 — Architectural Review: airlock-sandbox-provisioning

- Reviewer: System Architect (Stage 6, pre-PR)
- Branch: `fix/airlock-sandbox-provisioning` @ `98135e8` (2 commits ahead of `main`)
- Scope: `main..fix/airlock-sandbox-provisioning` — product + tests
- Gates re-run this pass: `go build ./...` PASS, `go vet ./...` PASS, `go test ./internal/sandbox/...` PASS (66)
- Verdict: **CLEAN — proceed to PR.** No BLOCKERs. 1 SHOULD-FIX (regression-guard gap), 2 NITs.

---

## Summary

The fix is correct, minimal, and structurally sound. Provisioning is invoked
inside `CreateWithOptions` via the **same** `Provisioner.ProvisionVM` /
`ProvisionSteps` builder the base VM uses, gated by a new `CreateOptions.Provision`
flag (default false = old behavior). Ordering (boot → provision → clone → network
lock) is correct for both local-worktree and remote-source paths and is guarded by
a unit test. Rollback on provision failure mirrors the sibling clone/network steps.
AC6 (setup/init unchanged) is preserved and regression-tested.

The single notable gap is that the **CLI wiring** (`newSandboxCmd` passing
`Provision: true`) — which is the exact locus of the original defect — has no
automated regression guard; it was validated only by live QA.

---

## Findings

### SHOULD-FIX

**S1 — The CLI wiring that triggers provisioning has no automated regression guard.**
`cmd/airlock/cli/cli.go:358,362` — `newSandboxCmd` now passes
`api.CreateOptions{Provision: true}` in both the `--json` and spinner branches.
There is no test file in `cmd/airlock/cli/` (cli.go is the only `.go` there), and
the integration harness (`test/integration/harness_test.go`) drives the `Manager`
directly, not the cobra command. Every unit test in `internal/sandbox` calls
`CreateWithOptions(..., {Provision: true})` explicitly, so **reverting
`Provision: true` in `cli.go` would leave the entire test suite green** — only live
QA would catch it. Given the original defect was precisely "the sandbox CLI path
never provisions," and this is load-bearing/high-revert-risk code, a thin guard is
warranted.
Recommendation: add a CLI-level (or integration-level) test asserting the `sandbox`
command reaches `CreateWithOptions` with `Provision: true` (e.g. inject a spy
`SandboxManager` into `Dependencies` and assert the captured opts). This is the one
thing the live QA pass masks. Not a merge blocker — the code is correct today — but
close it before this area churns again.

### NIT

**N1 — `provisionOptionsForRuntime` options-construction is a second, separate site
from setup's opts-building.** `internal/sandbox/create.go:294` vs. the wizard/flag
`provisionOpts` built in `cli.go` (`newSetupCmd` ~245, `init` ~905). The **step
assembly** is genuinely shared (both funnel through `ProvisionSteps`), so the
divergence class this ticket fixes cannot silently regress — good. But the two
paths still *invoke* provisioning at different layers (CLI loop vs. `ProvisionVM`
inside Create) and build their `ProvisionOptions` independently. A future required
runtime/baseline change to the per-ticket path would need touching both sites.
Intentional per plan scope (per-ticket = node-only baseline; setup = full stack),
and adequately documented in the `Provision` godoc — recording it so the residual
drift surface is known, not asking for a change.

**N2 — No nil-guard on `m.provisioner`.** `create.go:106` dereferences
`m.provisioner` whenever `opts.Provision` is set. `sandbox` is an `internal/`
package so no external embedder can construct a `Manager`, and every in-module
constructor (bootstrap + all tests) passes a non-nil provisioner, so this cannot
fire today. A defensive check returning a clear error (rather than a nil panic)
would be marginally friendlier if a future caller sets `Provision` without wiring
a provisioner. Optional.

---

## Correctness (lens 1)

- **Ordering, all paths:** provision runs after `createAndStartVM` and before both
  `cloneRemoteSource` (`create.go:125`) and `applyNetworkPolicy` (`create.go:139`).
  For **remote** sources the clone runs `ExecAsUser(..., "airlock", ...)`
  (`create.go:207`); the baseline "Creating airlock user" step
  (`internal/vm/lima/provision.go:61`) runs first, so the user exists before the
  clone. For **local** worktrees the mount is present at boot and "Preparing
  airlock home" (`provision.go:68`, `-xdev`-prune chown of `/home/airlock/projects`)
  makes the mountpoint traversable. No path leaves `Provision:true` with the
  airlock user missing before `ExecAsUser`. ✓
- **Rollback parity:** provision-failure handler (`create.go:107-118`) deletes the
  VM and marks the record `StateErrored`, identical to the clone
  (`create.go:128-135`) and network (`create.go:146-153`) handlers. No leaked VM,
  correct errored marking. Mount registration is downstream of provision, so
  nothing to unwind. ✓

## Contract / API (lens 2) — `## Contracts`

- **`NewManager` signature change** (`internal/sandbox/sandbox.go:58`): added
  required `provisioner api.Provisioner` in the 3rd position (grouped with the
  other VM-capability deps `provider`, `resetter`, which `limaProvider` also
  satisfies). Documented in the `NewManager` godoc.
- **Breaking-change surface:** none externally — `sandbox` is an `internal/`
  package, so Go forbids out-of-module import; no external embedder can be broken.
  All in-module call sites updated: `internal/bootstrap/bootstrap.go:67` (prod),
  `test/integration/harness_test.go` (integration), and 7 sites in
  `internal/sandbox/sandbox_test.go`. Build + vet + tests green.
- **`CreateOptions.Provision`** (`internal/api/sandbox.go`): new `bool`, zero value
  `false` = prior behavior. `CreateWithOptions` already existed on the
  `SandboxManager` interface, so no interface change. Backward-compatible. ✓
- **`limaProvider` implements `api.Provisioner`** (ProvisionVM/ProvisionSteps/
  SnapshotClean/HasCleanSnapshot) — confirmed; passed as provider+resetter+
  provisioner.

## Encapsulation / divergence-safety (lens 3)

Core plan goal met: setup and sandbox share **one** step-assembly builder
(`ProvisionSteps`). setup iterates its steps in the CLI for per-step TUI; sandbox
calls `ProvisionVM` (which iterates the same steps). There is **no duplicated
step list** that could drift. Residual: independent options-construction and
invocation sites (see N1) — a documented, in-scope trade-off, not a regression
vector for the fixed defect.

## Idempotency / safety (lens 4)

- Recreate: `CreateWithOptions` treats prior `errored`/`creating` records as
  recoverable, deletes the stale VM, and provisions a fresh one
  (`create.go:64-80`). A `running` record returns `ErrAlreadyExists` (no
  re-provision). ✓
- Baseline steps are individually idempotent (`id airlock || useradd`,
  `mkdir -p`, visudo-validated `mv`), so a re-run on a partially provisioned VM is
  safe. ✓
- `provisionOptionsForRuntime` (`create.go:294`) is total over `RuntimeType`:
  node → `InstallNode:true`, everything else (go/rust/python/unknown/empty) →
  baseline-only. No map lookup, no panic path. Covered by
  `TestProvisionOptionsForRuntime`. ✓

## Test quality (lens 5)

- `TestProvisionOptionsForRuntime` — pure mapping, 5 runtimes incl. unknown. ✓
- `TestCreateProvisionsNodeRuntime` / `NonNodeRuntime` — one ProvisionVM call,
  correct `InstallNode`. ✓
- `TestCreateProvisionOrdering` — **remote-source** (`gh:owner/repo`) +
  locking `cautious` profile; asserts provision precedes clone (ExecAsUser=0) and
  network apply (policies=0). This is the requested remote-path-with-`Provision`
  regression coverage. ✓
- `TestCreateNoProvisionWhenUnset` — AC6 invariant: setup shape
  (`SkipNetworkPolicy:true`, Provision unset) makes zero provisioner calls. ✓
- `TestCreateProvisionFailureRollsBack` — VM deleted + record errored. ✓
- AC1 baseline step labels ("Creating airlock user", "Preparing airlock home") are
  covered transitively by `internal/vm/lima/snapshot_test.go:220`
  (`TestProvisionSteps_BaselineOnly`) — the sandbox path calls the same builder,
  so re-asserting labels here would be redundant. Acceptable.
- Gap: CLI wiring — see S1.

## Security / least-authority (lens 6)

Provisioning installs the `airlock` NOPASSWD sudoers drop-in
(`internal/vm/lima/provision.go:26-31,62`) — visudo-validated before install, and
scoped to the per-ticket VM (each sandbox is its own Lima instance; isolation is
the product invariant). This is the **same** drop-in the base VM already gets, so
no privilege widening relative to the established baseline. Profile semantics
(AC7) untouched: no change to `resolveProfile`/`applyNetworkPolicy`/
`resolveResources`; provision does not read or mutate `prof.Mount`/`prof.Network`,
and is ordered before the network lock exactly as setup already does. ✓

## Notes on what the live QA pass may have masked

- **S1** is the material one: QA built from the fixed source, so the absent
  automated guard on the CLI `Provision: true` wiring is invisible in a green live
  run.
- QA's own non-blocking observations (the cosmetic `status` "locked" label while
  egress is open; the `echo/printf >` shell-redirection artifact worked around
  with `cp`) are both **pre-existing and outside this diff's changed files**
  (create.go/sandbox.go/api/sandbox.go/cli.go/bootstrap.go). Confirmed not
  introduced here; leave for separate follow-ups.

---

## Recommendation

**Proceed to PR.** The change is architecturally clean and the ACs are satisfied
(unit + live). S1 is a cheap regression-guard follow-up, not a merge blocker — but
should be closed before this create/provision path churns again, since it guards
the exact defect this ticket fixed. Merge remains HITL.

---

## Merge decision (Stage 6 close-out)

- **Decision: MERGED.** Approved by human gate (HITL).
- PR #14 — `fix(sandbox): provision per-ticket VMs via shared ProvisionSteps` —
  merged to `main` as `e997d47`. CI green (build, vet, test, lint).
- Follow-on PR #15 — `fix(sandbox): make concurrent Create race-free and
  deterministic` — merged to `main` as `2833ab7`. Emerged post-merge during the
  v0.3.0 tag build, which ran `go test -race` and hit a fatal data race in
  `TestCreateConcurrentDuplicate`. Root causes: `SandboxInfo.State` mutated
  outside the mutex, no name reservation for concurrent `Create`, unsynchronized
  test doubles. All three fixed; suite passes 100% under `-race`.
- Docs: no update required. `README.md` already documents
  `airlock sandbox <path-or-url>` as creating a provisioned isolated sandbox —
  this ticket restored the documented behavior rather than changing it.
  `TASKS.md:26` already records the atomic name reservation (TOCTOU fix).
  No CHANGELOG exists in this repo.
- Retro: complete (`retro.md`).

### Carried forward (open, not blocking this ticket)

1. **S1 — CLI wiring has no automated regression guard.** Still open.
   `cmd/airlock/cli/cli.go:358,362`. Reverting `Provision: true` leaves the whole
   suite green. Guards the exact defect this ticket fixed — close before this
   path churns again.
2. **`-race` absent from CI and drydock QA gate commands.** The v0.3.0 race was
   invisible to every gate and only surfaced at tag time. Add `-race` for
   packages with concurrent state (`internal/sandbox`).
3. **N1 — `ProvisionOptions` built at two independent sites.** Recorded as known
   residual drift surface; no change requested.

**Ticket closed.**
