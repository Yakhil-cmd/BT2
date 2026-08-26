# Q1044: ReRun — initmaxfail bypass under http pprof

## Question
Starting from `--http-pprof` enabled for debugging, can an attacker who fails only the initial sync so the --init-max-failures path governs drive the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping to a state where the phase-selection logic picks the wrong limit and the container either never exits or exits immediately, defeating “the effective failure budget matches the documented phase semantics” and causing denial of service via premature exit, or unbounded retry against the remote?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Fails only the initial sync so the --init-max-failures path governs. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the phase-selection logic picks the wrong limit and the container either never exits or exits immediately
- Invariant to test: the effective failure budget matches the documented phase semantics
- Expected Immunefi impact: denial of service via premature exit, or unbounded retry against the remote (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: curl the bound port from an unauthorized context and assert nothing sensitive (argv, profiles, counters) is returned
