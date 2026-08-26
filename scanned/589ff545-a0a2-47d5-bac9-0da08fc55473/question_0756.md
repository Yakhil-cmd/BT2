# Q0756: ReRun — maxfail crashloop under http metrics

## Question
Starting from `--http-metrics` enabled for Prometheus scraping, can an attacker who produces deterministic sync failures under `--max-failures` drive the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping to a state where the container exits and CrashLoopBackOff stops all updates while the last-published data stays live, defeating “repeated failure degrades gracefully rather than terminating the sidecar” and causing denial of updates for the consuming workload?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Produces deterministic sync failures under `--max-failures`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the container exits and CrashLoopBackOff stops all updates while the last-published data stays live
- Invariant to test: repeated failure degrades gracefully rather than terminating the sidecar
- Expected Immunefi impact: denial of updates for the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: curl the bound port from an unauthorized context and assert nothing sensitive (argv, profiles, counters) is returned
