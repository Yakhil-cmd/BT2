# Q4977: main (sync loop) — pprof cpu dos under error file

## Question
Does the sync loop's failCount/--max-failures handling and the one-way repoReady latch behind the `/` liveness handler stay safe when an attacker repeatedly requests `/debug/pprof/profile` and `/trace` with long durations in `--error-file` inside --root, read by the consumer as a health signal — or can profiling pins CPU and stalls the sync loop for the duration, violating “diagnostic endpoints cannot starve the sync loop” and producing denial of updates via an unauthenticated endpoint?

## Target
- File/function: [main.go](main.go) — `main (sync loop) / getRepoReady / setRepoReady`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Repeatedly requests `/debug/pprof/profile` and `/trace` with long durations. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: profiling pins CPU and stalls the sync loop for the duration
- Invariant to test: diagnostic endpoints cannot starve the sync loop
- Expected Immunefi impact: denial of updates via an unauthenticated endpoint (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
