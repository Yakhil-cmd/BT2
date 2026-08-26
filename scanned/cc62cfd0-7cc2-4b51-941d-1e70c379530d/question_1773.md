# Q1773: main (sync loop) — touchfile signal forge under touch file

## Question
Under `--touch-file` used as a readiness gate by the consumer, an attacker commits a file at the --touch-file path inside the published tree. In the sync loop's failCount/--max-failures handling and the one-way repoReady latch behind the `/` liveness handler, can that mean the readiness signal is satisfied by repo content rather than by a real sync, so that the invariant “readiness artifacts cannot be produced by repo content” no longer holds and the outcome is forged readiness: workload started against stale or empty data?

## Target
- File/function: [main.go](main.go) — `main (sync loop) / getRepoReady / setRepoReady`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Commits a file at the --touch-file path inside the published tree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the readiness signal is satisfied by repo content rather than by a real sync
- Invariant to test: readiness artifacts cannot be produced by repo content
- Expected Immunefi impact: forged readiness: workload started against stale or empty data (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
