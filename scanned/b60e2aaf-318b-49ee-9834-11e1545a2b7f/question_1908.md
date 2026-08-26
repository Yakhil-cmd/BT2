# Q1908: ReRun — touchfile signal forge under sync on signal

## Question
Starting from `--sync-on-signal` configured, can an attacker who commits a file at the --touch-file path inside the published tree drive the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping to a state where the readiness signal is satisfied by repo content rather than by a real sync, defeating “readiness artifacts cannot be produced by repo content” and causing forged readiness: workload started against stale or empty data?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Commits a file at the --touch-file path inside the published tree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the readiness signal is satisfied by repo content rather than by a real sync
- Invariant to test: readiness artifacts cannot be produced by repo content
- Expected Immunefi impact: forged readiness: workload started against stale or empty data (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
