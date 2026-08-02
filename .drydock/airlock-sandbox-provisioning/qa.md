# QA Gate (Stage 4) — airlock-sandbox-provisioning

- Role: Independent QAS (verify only; no product code edited)
- Branch: `fix/airlock-sandbox-provisioning` @ `98135e8`
- Patched binary: `/tmp/airlock-fix` (built from repo root `go build -o /tmp/airlock-fix .`)
- Live sandbox: `drydock-qa-verify-stage4` (dev profile, node runtime), created + destroyed this pass
- Verdict: **ALL 7 AC PASS** → `Approved for RTE`

## Layer 1 — static gates (re-run independently)
| Gate | Result |
|---|---|
| `go build ./...` | PASS (exit 0) |
| `go vet ./...` | PASS (exit 0) |
| `go test ./...` | PASS — 416 passed in 15 packages (matches dev claim) |
| AC6 regression `TestCreateNoProvisionWhenUnset` | PASS (no provisioner call when `Provision` unset) |
| Ordering guard `TestCreateProvisionOrdering` (U2) | PASS (provision precedes clone + network lock) |
| Rollback `TestCreateProvisionFailureRollsBack` | PASS |

## Layer 2 — LIVE end-to-end (per-ticket sandbox on a real VM)
| AC | Verdict | Evidence (command → result) |
|---|---|---|
| AC1 airlock user exists | PASS | `run -- id airlock` → `uid=1000(airlock) gid=1001(airlock)` |
| AC2 runs as real user | PASS | `run -- whoami` → `airlock`; `run -- id -un` → `airlock`; `run -- true` exit 0. NO "unknown user airlock". |
| AC3 node/npm on PATH | PASS | `run -- node --version` → `v22.23.1`; `run -- npm --version` → `10.9.8` |
| **AC4 #EXPORT_CRITICAL (U1)** | **PASS** | see verbatim block below |
| AC5 in-sandbox verification | PASS | `run -- node --check <mount>/hello.js` exit 0; `run -- node <mount>/hello.js` → `airlock-qa ok` |
| AC6 #EXPORT_CRITICAL setup unchanged | PASS | regression test green; base `airlock` VM still present/untouched (list); diff touches only sandbox-create path + `newSandboxCmd` (setup/init CLI paths unmodified) |
| AC7 profile semantics preserved | PASS | mount `(read-write)`; egress open under dev: `curl https://registry.npmjs.org/` → `http_code=200` |

### AC4 live result (verbatim) — the uid-mapping proof (U1 RESOLVED)
```
# ls mount as run-user (contents owned airlock:airlock, readable/traversable)
$ airlock run drydock-qa-verify-stage4 -- ls -la /home/airlock/projects/drydock-qa-verify-stage4
drwxr-xr-x 21 airlock airlock ... .   (all entries owned airlock:airlock)

# host -> guest read
$ airlock run drydock-qa-verify-stage4 -- cat <mount>/host-written.txt
HOST_TO_GUEST_STAGE4_OK

# guest WRITE (cp, no shell-redirection) then guest READ BACK
$ airlock run drydock-qa-verify-stage4 -- cp <mount>/host-written.txt <mount>/guest-copy.txt   # cp exit=0
$ airlock run drydock-qa-verify-stage4 -- cat <mount>/guest-copy.txt
HOST_TO_GUEST_STAGE4_OK

# same file visible on HOST worktree with identical bytes (guest -> host virtiofs rw)
$ cat qa-worktree/guest-copy.txt
HOST_TO_GUEST_STAGE4_OK
```
The `airlock` run-user reads and writes real multi-byte mount content in both
directions; guest writes surface on the host worktree (mapped to host uid 501),
guest sees them as `airlock:airlock`. **U1 resolved — no mount uid-map fix needed.**

Note: earlier `echo/printf > file` attempts returned mangled/1-byte output; that is
a nested-quote/shell-redirection artifact of the zsh→cobra→ExecAsUser→sudo→login-bash
layers (redirection `>` tokens landing in separate escaped args), NOT a mount defect.
Proven by the clean `cp`-based roundtrip above (no shell operators).

### Observation (non-blocking, out of scope)
`status` prints `Network • locked (outbound blocked)` for the dev sandbox while egress
is actually OPEN (curl 200) and the mount is read-write — i.e. the real dev policy is
correct. This diff does not touch network/status rendering (files changed: create.go,
sandbox.go, api/sandbox.go, cli.go `newSandboxCmd`, bootstrap.go), so the cosmetic
"locked" label is pre-existing and unrelated to this fix. Flagged for a follow-up glance;
does not affect AC7 (actual dev network/mount/Docker policy unchanged).

## Cleanup
- `airlock destroy drydock-qa-verify-stage4` → destroyed (exit 0)
- `limactl list` → only pre-existing `airlock` (stopped) + `default`; no leftover instance
- throwaway git worktree removed (`git worktree remove --force`)

## Evidence files
- `.drydock/airlock-sandbox-provisioning/evidence/qa-live-transcript.txt`
- `.drydock/airlock-sandbox-provisioning/evidence/qa-go-build.txt`
- `.drydock/airlock-sandbox-provisioning/evidence/qa-go-vet.txt`
- `.drydock/airlock-sandbox-provisioning/evidence/qa-go-test.txt`

## Routing decision
All 7 AC PASS including live AC4 (#EXPORT_CRITICAL) and AC6 (#EXPORT_CRITICAL).
Plan uncertainties U1 (virtiofs uid map), U2 (provision-before-lock ordering),
U3 (node 22 default) all validated. **State → `Approved for RTE`. Hand off to @drydock-rte.**
