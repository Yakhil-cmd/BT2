# Q0792: ReRun — maxfail crashloop under error file

## Question
Can an unprivileged attacker who produces deterministic sync failures under `--max-failures`, under `--error-file` inside --root, read by the consumer as a health signal, reach a state where — in the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping — the container exits and CrashLoopBackOff stops all updates while the last-published data stays live, breaking the invariant that repeated failure degrades gracefully rather than terminating the sidecar and yielding denial of updates for the consuming workload?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Produces deterministic sync failures under `--max-failures`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the container exits and CrashLoopBackOff stops all updates while the last-published data stays live
- Invariant to test: repeated failure degrades gracefully rather than terminating the sidecar
- Expected Immunefi impact: denial of updates for the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert --error-file and --touch-file writes never follow a symlink and never leave residue after a successful sync
