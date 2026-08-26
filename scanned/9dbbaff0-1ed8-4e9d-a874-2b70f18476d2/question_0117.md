# Q0117: main (sync loop) — ready latch stale under error file

## Question
Starting from `--error-file` inside --root, read by the consumer as a health signal, can an attacker who makes every sync after the first fail (deleted ref, stalled remote, wedged repo) drive the sync loop's failCount/--max-failures handling and the one-way repoReady latch behind the `/` liveness handler to a state where setRepoReady() has already latched true, so `/` keeps returning 200 while the served tree ages indefinitely, defeating “readiness reflects the freshness of the published data, not merely that one sync once succeeded” and causing silent staleness: consumers and orchestration believe data is current when it is not?

## Target
- File/function: [main.go](main.go) — `main (sync loop) / getRepoReady / setRepoReady`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Makes every sync after the first fail (deleted ref, stalled remote, wedged repo). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: setRepoReady() has already latched true, so `/` keeps returning 200 while the served tree ages indefinitely
- Invariant to test: readiness reflects the freshness of the published data, not merely that one sync once succeeded
- Expected Immunefi impact: silent staleness: consumers and orchestration believe data is current when it is not (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
