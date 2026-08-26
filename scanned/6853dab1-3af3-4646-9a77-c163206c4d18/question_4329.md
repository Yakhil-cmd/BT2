# Q4329: main (sync loop) — log volume dos under error file

## Question
Can an unprivileged attacker who drives high-verbosity logging (huge ref lists, fetch verbosity, hook output), under `--error-file` inside --root, read by the consumer as a health signal, reach a state where — in the sync loop's failCount/--max-failures handling and the one-way repoReady latch behind the `/` liveness handler — log volume fills the node's log partition, breaking the invariant that log output is bounded per sync and yielding node-level disk exhaustion affecting other workloads?

## Target
- File/function: [main.go](main.go) — `main (sync loop) / getRepoReady / setRepoReady`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Drives high-verbosity logging (huge ref lists, fetch verbosity, hook output). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: log volume fills the node's log partition
- Invariant to test: log output is bounded per sync
- Expected Immunefi impact: node-level disk exhaustion affecting other workloads (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: curl the bound port from an unauthorized context and assert nothing sensitive (argv, profiles, counters) is returned
