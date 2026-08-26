# Q5112: ReRun — pprof cpu dos under onetime

## Question
Can an unprivileged attacker who repeatedly requests `/debug/pprof/profile` and `/trace` with long durations, under `--one-time` mode used as an init container, reach a state where — in the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping — profiling pins CPU and stalls the sync loop for the duration, breaking the invariant that diagnostic endpoints cannot starve the sync loop and yielding denial of updates via an unauthenticated endpoint?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Repeatedly requests `/debug/pprof/profile` and `/trace` with long durations. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: profiling pins CPU and stalls the sync loop for the duration
- Invariant to test: diagnostic endpoints cannot starve the sync loop
- Expected Immunefi impact: denial of updates via an unauthenticated endpoint (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
