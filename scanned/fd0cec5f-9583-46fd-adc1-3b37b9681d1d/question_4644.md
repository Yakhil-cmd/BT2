# Q4644: ReRun — pprof exposure under http metrics

## Question
Starting from `--http-metrics` enabled for Prometheus scraping, can an attacker who reaches the `--http-bind` port from another pod and requests `/debug/pprof/cmdline`, `/profile`, or `/trace` drive the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping to a state where the full command line (including any secret-bearing flags) and process memory profiles are returned to an unauthenticated caller, defeating “no unauthenticated endpoint discloses process state or arguments” and causing credential and internal-state disclosure to any in-cluster peer?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Reaches the `--http-bind` port from another pod and requests `/debug/pprof/cmdline`, `/profile`, or `/trace`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the full command line (including any secret-bearing flags) and process memory profiles are returned to an unauthenticated caller
- Invariant to test: no unauthenticated endpoint discloses process state or arguments
- Expected Immunefi impact: credential and internal-state disclosure to any in-cluster peer (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: curl the bound port from an unauthorized context and assert nothing sensitive (argv, profiles, counters) is returned
