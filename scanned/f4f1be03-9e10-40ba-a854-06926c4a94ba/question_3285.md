# Q3285: main (sync loop) — errorfile secret under http pprof

## Question
Starting from `--http-pprof` enabled for debugging, can an attacker who forces an auth-path error while credentials are in the message or args drive the sync loop's failCount/--max-failures handling and the one-way repoReady latch behind the `/` liveness handler to a state where the secret is serialised into --error-file inside the shared volume, defeating “secrets never reach the error file” and causing credential disclosure to the co-tenant workload?

## Target
- File/function: [main.go](main.go) — `main (sync loop) / getRepoReady / setRepoReady`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Forces an auth-path error while credentials are in the message or args. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the secret is serialised into --error-file inside the shared volume
- Invariant to test: secrets never reach the error file
- Expected Immunefi impact: credential disclosure to the co-tenant workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert --error-file and --touch-file writes never follow a symlink and never leave residue after a successful sync
