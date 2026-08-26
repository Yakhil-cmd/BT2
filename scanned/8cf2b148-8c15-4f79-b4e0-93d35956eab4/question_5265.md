# Q5265: main (sync loop) — metrics info leak under http metrics

## Question
Does the sync loop's failCount/--max-failures handling and the one-way repoReady latch behind the `/` liveness handler stay safe when an attacker scrapes `/metrics` from another pod in `--http-metrics` enabled for Prometheus scraping — or can sync counts, timings, and hook/askpass error counters reveal repository activity and auth failures to unauthorised callers, violating “metrics do not disclose sensitive operational detail to unauthenticated callers” and producing information disclosure enabling targeted follow-on attacks?

## Target
- File/function: [main.go](main.go) — `main (sync loop) / getRepoReady / setRepoReady`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Scrapes `/metrics` from another pod. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: sync counts, timings, and hook/askpass error counters reveal repository activity and auth failures to unauthorised callers
- Invariant to test: metrics do not disclose sensitive operational detail to unauthenticated callers
- Expected Immunefi impact: information disclosure enabling targeted follow-on attacks (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
