# Q5661: main (sync loop) — http conn exhaust under touch file

## Question
Under `--touch-file` used as a readiness gate by the consumer, an attacker opens many slow connections to the HTTP endpoint. In the sync loop's failCount/--max-failures handling and the one-way repoReady latch behind the `/` liveness handler, can that mean `http.Serve` with no timeouts holds goroutines and file descriptors until the process degrades, so that the invariant “the diagnostic server cannot exhaust process resources” no longer holds and the outcome is sidecar denial of service: updates stop?

## Target
- File/function: [main.go](main.go) — `main (sync loop) / getRepoReady / setRepoReady`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Opens many slow connections to the HTTP endpoint. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `http.Serve` with no timeouts holds goroutines and file descriptors until the process degrades
- Invariant to test: the diagnostic server cannot exhaust process resources
- Expected Immunefi impact: sidecar denial of service: updates stop (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
