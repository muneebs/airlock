# Airlock Core Principles

These principles govern all design and implementation decisions in Airlock. Every contribution must satisfy these rules. When in doubt, refer back to these — they override convenience, habit, or "how it's always been done."

---

## 1. Maintainability

Code must be easy to understand, modify, and extend — especially by someone who didn't write it.

- **Packages are boundaries.** Each package (`config`, `profile`, `detect`, `sandbox`, `vm`, `mount`, `network`) owns a single domain. Cross-package dependencies go through interfaces, not concrete types.
- **Explicit over implicit.** No magic globals, no hidden state, no reflect-based cleverness. If a reader can't trace the data flow, it's wrong.
- **Small, reviewed PRs.** Changes should be reviewable in under 10 minutes. If a PR needs a 500-word explanation, break it up.
- **Tests as documentation.** Every exported function should have a test that shows how to use it. Tests are the first place a new contributor looks.
- **Go standard style.** `gofmt`, `golint`, `go vet`. No bikeshedding — follow the standard.

---

## 2. Scalability

Airlock must respect the machine it runs on. Creating isolated environments is resource-intensive — the tool must be intelligent about it.

- **Know the limits before you hit them.** The `sysutil` package proactively detects available CPU cores, memory, and disk. Sandboxes refuse to start if resources are insufficient, rather than failing mid-creation.
- **One VM per sandbox, but not forever.** Ephemeral sandboxes (`--ephemeral`) are the default for one-off runs. They clean up after themselves. Long-lived sandboxes must be explicitly created.
- **Resource defaults are conservative.** Default VM allocation is 2 CPU / 4GiB / 20GiB — enough for most projects. The tool never assumes the user has a workstation-class machine.
- **No background resource leaks.** Every goroutine has a cancellation path. Every VM has a stop path. Temp files are cleaned up. File handles are closed.
- **Concurrency where it helps, not everywhere.** Parallel VM operations when possible, but never at the cost of correctness. A slow sequential creation is better than a fast race condition.

---

## 3. Userability

Security must be accessible. The safest tool is the one people actually use.

- **Safe defaults, no expertise required.** The `cautious` security profile is the default. A user running `airlock sandbox gh:user/repo` gets strong isolation without reading any documentation.
- **Tell the user what happened, not what went wrong.** When a security policy blocks an action, explain what the app tried to do and how to change it — don't just print a stack trace or an iptables error.
- **Fewer flags, not more.** If a common workflow needs 5 flags, the API is wrong. Add a higher-level command instead.
- **Config is optional.** Zero-config should work for 90% of users. Config files (`airlock.toml`, `airlock.yaml`) are for power users with reusable defaults.
- **One correct way.** Don't provide three ways to do the same thing. Pick the best one, document it, and make it obvious.

---

## 4. DRY (Don't Repeat Yourself)

Duplication is the enemy of correctness. Every piece of knowledge should have a single, authoritative representation.

- **Interfaces are contracts.** `RuntimeDetector`, `SandboxManager`, `NetworkController` — define the interface once, implement it once. If you're copy-pasting a method signature, make it an interface.
- **Plugin-style extensibility.** New runtime detectors (`detect.RuntimeDetector`), new security profiles (`profile.Profile`), new VM backends (`vm.Provider`) should be addable by implementing an interface and registering it — not by modifying existing code.
- **Shared validation.** Config parsing, mount path resolution, and security policy enforcement each happen in exactly one place. All callers go through that place.
- **Documentation is code.** Doc comments on exported types and functions are the source of truth. README and godoc render from the same information. Don't maintain two descriptions of the same thing.
- **No duplicate config schemas.** The same struct handles both TOML and YAML. One validation path, one set of defaults, one source of truth.

---

## 5. SOLID Principles

### Single Responsibility
Each package does one thing. `config` parses config. `detect` detects runtimes. `profile` defines security policies. `sandbox` orchestrates. If a package's name needs "and" in it, split it.

### Open/Closed
Add behavior by implementing interfaces, not by editing existing functions. New runtime detectors, new profiles, new VM backends — all register themselves. The core never switches on a type enum.

### Liskov Substitution
Any `vm.Provider` can replace any other. Any `detect.RuntimeDetector` can replace any other. Tests use fakes. Production uses real implementations. No `if concreteType` checks.

### Interface Segregation
Small, focused interfaces. `NetworkController` has `Lock()` and `Unlock()`. `MountManager` has `Register()` and `Unregister()`. Don't build god-interfaces with 20 methods.

### Dependency Inversion
High-level packages (`sandbox`, `cmd`) depend on interfaces defined in their own package (or in a shared `api` package). Low-level packages (`vm/lima`, `network/iptables`) implement those interfaces. The CLI never imports Lima directly.

---

## Enforcement

- **PR reviews** must explicitly check against these principles. Reviewers: cite the principle by name when requesting a change.
- **CI** runs `go vet`, `golint`, `go test -race`, and checks test coverage. Coverage below 70% on new packages is a block.
- **ARCHITECTURE.md** (coming) will document package boundaries and dependency flow. New packages must be added there before code is written.