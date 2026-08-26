# Q1116: ReRun — initmaxfail bypass under error file

## Question
Under `--error-file` inside --root, read by the consumer as a health signal, an attacker fails only the initial sync so the --init-max-failures path governs. In the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping, can that mean the phase-selection logic picks the wrong limit and the container either never exits or exits immediately, so that the invariant “the effective failure budget matches the documented phase semantics” no longer holds and the outcome is denial of service via premature exit, or unbounded retry against the remote?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Fails only the initial sync so the --init-max-failures path governs. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the phase-selection logic picks the wrong limit and the container either never exits or exits immediately
- Invariant to test: the effective failure budget matches the documented phase semantics
- Expected Immunefi impact: denial of service via premature exit, or unbounded retry against the remote (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
