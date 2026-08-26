# Q1404: ReRun — hash pinned sleepforever under http metrics

## Question
Under `--http-metrics` enabled for Prometheus scraping, an attacker gets the sync to conclude `hash == git.ref` when the ref is not actually a pinned hash (ref name equal to a hash, peeled tag). In the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping, can that mean sleepForever() is entered and the sidecar never syncs again for the container's lifetime, so that the invariant “the terminal 'pinned hash' state is only reached for a genuinely pinned hash” no longer holds and the outcome is permanent denial of updates, including security updates, to the consumer?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Gets the sync to conclude `hash == git.ref` when the ref is not actually a pinned hash (ref name equal to a hash, peeled tag). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: sleepForever() is entered and the sidecar never syncs again for the container's lifetime
- Invariant to test: the terminal 'pinned hash' state is only reached for a genuinely pinned hash
- Expected Immunefi impact: permanent denial of updates, including security updates, to the consumer (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
