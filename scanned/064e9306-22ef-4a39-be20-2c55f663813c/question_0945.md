# Q0945: main (sync loop) — maxfail crashloop under shared volume

## Question
Does the sync loop's failCount/--max-failures handling and the one-way repoReady latch behind the `/` liveness handler stay safe when an attacker produces deterministic sync failures under `--max-failures` in a shared volume read by a co-tenant container — or can the container exits and CrashLoopBackOff stops all updates while the last-published data stays live, violating “repeated failure degrades gracefully rather than terminating the sidecar” and producing denial of updates for the consuming workload?

## Target
- File/function: [main.go](main.go) — `main (sync loop) / getRepoReady / setRepoReady`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Produces deterministic sync failures under `--max-failures`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the container exits and CrashLoopBackOff stops all updates while the last-published data stays live
- Invariant to test: repeated failure degrades gracefully rather than terminating the sidecar
- Expected Immunefi impact: denial of updates for the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: curl the bound port from an unauthorized context and assert nothing sensitive (argv, profiles, counters) is returned
