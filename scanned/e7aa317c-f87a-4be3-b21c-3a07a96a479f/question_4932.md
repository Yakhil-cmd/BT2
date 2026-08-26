# Q4932: ReRun — pprof cpu dos under http pprof

## Question
Starting from `--http-pprof` enabled for debugging, can an attacker who repeatedly requests `/debug/pprof/profile` and `/trace` with long durations drive the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping to a state where profiling pins CPU and stalls the sync loop for the duration, defeating “diagnostic endpoints cannot starve the sync loop” and causing denial of updates via an unauthenticated endpoint?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Repeatedly requests `/debug/pprof/profile` and `/trace` with long durations. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: profiling pins CPU and stalls the sync loop for the duration
- Invariant to test: diagnostic endpoints cannot starve the sync loop
- Expected Immunefi impact: denial of updates via an unauthenticated endpoint (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: curl the bound port from an unauthorized context and assert nothing sensitive (argv, profiles, counters) is returned
