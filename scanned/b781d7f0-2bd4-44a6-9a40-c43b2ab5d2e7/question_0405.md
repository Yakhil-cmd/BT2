# Q0405: main (sync loop) — ready before publish under http metrics

## Question
Starting from `--http-metrics` enabled for Prometheus scraping, can an attacker who times a failure between publish and the loop's setRepoReady()/touch-file update drive the sync loop's failCount/--max-failures handling and the one-way repoReady latch behind the `/` liveness handler to a state where readiness and the touch-file disagree with the actual link target, defeating “readiness signals are consistent with the published link” and causing orchestration routing traffic to a workload with wrong content?

## Target
- File/function: [main.go](main.go) — `main (sync loop) / getRepoReady / setRepoReady`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Times a failure between publish and the loop's setRepoReady()/touch-file update. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: readiness and the touch-file disagree with the actual link target
- Invariant to test: readiness signals are consistent with the published link
- Expected Immunefi impact: orchestration routing traffic to a workload with wrong content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
