# Q1341: main (sync loop) — hash pinned sleepforever under http pprof

## Question
Under `--http-pprof` enabled for debugging, an attacker gets the sync to conclude `hash == git.ref` when the ref is not actually a pinned hash (ref name equal to a hash, peeled tag). In the sync loop's failCount/--max-failures handling and the one-way repoReady latch behind the `/` liveness handler, can that mean sleepForever() is entered and the sidecar never syncs again for the container's lifetime, so that the invariant “the terminal 'pinned hash' state is only reached for a genuinely pinned hash” no longer holds and the outcome is permanent denial of updates, including security updates, to the consumer?

## Target
- File/function: [main.go](main.go) — `main (sync loop) / getRepoReady / setRepoReady`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Gets the sync to conclude `hash == git.ref` when the ref is not actually a pinned hash (ref name equal to a hash, peeled tag). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: sleepForever() is entered and the sidecar never syncs again for the container's lifetime
- Invariant to test: the terminal 'pinned hash' state is only reached for a genuinely pinned hash
- Expected Immunefi impact: permanent denial of updates, including security updates, to the consumer (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert --error-file and --touch-file writes never follow a symlink and never leave residue after a successful sync
