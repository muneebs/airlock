# Retro: airlock-sandbox-provisioning

- Ticket state: Merged (PR #14). Follow-on release blocker fixed on
  `fix/sandbox-create-concurrency-race` (PR #15, commit `56065c6`) — see note below.

## What went well

- Spec did the root-cause work upfront (two defects, exact file:line refs,
  code-path diff between `setup` and `sandbox`) — plan needed zero rediscovery.
- Risk explicitly set to NORMAL with reasoning recorded in spec.md, heading off
  a bootstrap deadlock (verifying the sandbox fix *inside* the broken sandbox).
  Worth reusing verbatim as a rule: when a ticket fixes the isolation mechanism
  itself, verify on host tooling, not through the mechanism being fixed.
- Plan made one clean architectural call (share `ProvisionSteps`, inject
  `Provisioner` into `Manager`, order provision before clone/network-lock) and
  front-loaded the load-bearing uncertainty (U1 virtiofs uid-map) instead of
  discovering it at QA.
- QAS did a real live boot + guest read/write roundtrip, not just step-sequence
  assertions — caught nothing wrong, but was the only thing that could have
  caught U1.
- No gate bounced. Spec → Plan → Implement → QA (7/7 AC) → Review (CLEAN, 1
  non-blocking SHOULD-FIX) → PR → Merge, straight through.

## What slowed us down / where it nearly bounced

- Stage 6 review's S1 (CLI wiring `Provision: true` has no automated
  regression guard — only live QA would catch a revert) was correctly flagged
  as non-blocking but **not closed** before merge. It's exactly the kind of gap
  that bites later since it guards the original defect's exact locus.
- Real bounce happened *after* merge, outside the drydock trail: tagging
  v0.3.0 hit a fatal `concurrent map read and map write` in
  `TestCreateConcurrentDuplicate`. Root cause: CI runs `go test` without
  `-race`, so a genuine data race (SandboxInfo.State mutated outside the
  mutex, a name-reservation gap letting two concurrent `Create`s for the same
  name both proceed, unsynchronized test doubles) shipped past Stage 4/6
  undetected. Diagnosed and fixed same-day, verified at 500-iteration
  `-race` stress, PR #15. But it's a real gap: this ticket's own QA/review
  gates ran `go test ./...` without `-race` and both reported PASS.

## Concrete improvements

1. **Add `-race` to the CI test job and to drydock QA's standard gate command**
   for any package with concurrent state (`internal/sandbox` qualifies). This
   ticket proved `go test` and `go test -race` disagree by 24.5 percentage
   points in failure rate on the same code — race-free-looking is not
   race-free.
2. **Close S1-class findings before merge, not after**, when the flagged gap
   sits on the exact code path the ticket just fixed (CLI wiring that only
   live QA exercises). A cheap spy-based CLI test would have cost less than
   writing the finding up.
3. Nothing to extract into `patterns_library/` yet — see below.

## patterns_library — rule of three

Candidate (first use only — do not extract yet):

- **Pattern:** share one step-assembly builder across two invocation sites
  (CLI-layer iteration for TUI feedback vs. in-process call for a coarser
  progress callback) instead of duplicating the step list, gated by a bool
  option defaulting to old behavior.
  **Status:** candidate (first use: `airlock-sandbox-provisioning`,
  `internal/sandbox/create.go` `CreateWithOptions` + `cmd/airlock/cli/cli.go`
  `newSetupCmd`, 2026-07-22)

No `patterns_library/` directory exists in this repo yet — nothing to extract
into on a second use until one occurs; this candidate is the seed.
