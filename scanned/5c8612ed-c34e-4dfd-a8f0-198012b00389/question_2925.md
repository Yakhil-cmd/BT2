# Q2925: main (sync loop) — errorfile content injection under http bind

## Question
Under a deployment with `--http-bind` reachable from other pods in the cluster, an attacker gets attacker-controlled bytes (ref names, server stderr, submodule URLs) into a logged error. In the sync loop's failCount/--max-failures handling and the one-way repoReady latch behind the `/` liveness handler, can that mean the JSON payload written to the shared volume carries injected structure that a consumer parser misreads, so that the invariant “error-file content is strictly encoded and attacker bytes cannot alter its structure” no longer holds and the outcome is forged health signals driving the consumer to act on false state?

## Target
- File/function: [main.go](main.go) — `main (sync loop) / getRepoReady / setRepoReady`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Gets attacker-controlled bytes (ref names, server stderr, submodule URLs) into a logged error. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the JSON payload written to the shared volume carries injected structure that a consumer parser misreads
- Invariant to test: error-file content is strictly encoded and attacker bytes cannot alter its structure
- Expected Immunefi impact: forged health signals driving the consumer to act on false state (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
