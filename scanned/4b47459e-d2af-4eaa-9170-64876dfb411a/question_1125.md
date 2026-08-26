# Q1125: main (sync loop) — initmaxfail bypass under touch file

## Question
Starting from `--touch-file` used as a readiness gate by the consumer, can an attacker who fails only the initial sync so the --init-max-failures path governs drive the sync loop's failCount/--max-failures handling and the one-way repoReady latch behind the `/` liveness handler to a state where the phase-selection logic picks the wrong limit and the container either never exits or exits immediately, defeating “the effective failure budget matches the documented phase semantics” and causing denial of service via premature exit, or unbounded retry against the remote?

## Target
- File/function: [main.go](main.go) — `main (sync loop) / getRepoReady / setRepoReady`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Fails only the initial sync so the --init-max-failures path governs. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the phase-selection logic picks the wrong limit and the container either never exits or exits immediately
- Invariant to test: the effective failure budget matches the documented phase semantics
- Expected Immunefi impact: denial of service via premature exit, or unbounded retry against the remote (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: curl the bound port from an unauthorized context and assert nothing sensitive (argv, profiles, counters) is returned
