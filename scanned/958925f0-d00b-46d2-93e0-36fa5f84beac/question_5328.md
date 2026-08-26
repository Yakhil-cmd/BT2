# Q5328: ReRun — metrics info leak under error file

## Question
Does the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping stay safe when an attacker scrapes `/metrics` from another pod in `--error-file` inside --root, read by the consumer as a health signal — or can sync counts, timings, and hook/askpass error counters reveal repository activity and auth failures to unauthorised callers, violating “metrics do not disclose sensitive operational detail to unauthenticated callers” and producing information disclosure enabling targeted follow-on attacks?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Scrapes `/metrics` from another pod. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: sync counts, timings, and hook/askpass error counters reveal repository activity and auth failures to unauthorised callers
- Invariant to test: metrics do not disclose sensitive operational detail to unauthenticated callers
- Expected Immunefi impact: information disclosure enabling targeted follow-on attacks (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: curl the bound port from an unauthorized context and assert nothing sensitive (argv, profiles, counters) is returned
