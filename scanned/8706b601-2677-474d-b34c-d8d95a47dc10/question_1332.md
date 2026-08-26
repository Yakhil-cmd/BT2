# Q1332: ReRun — hash pinned sleepforever under http bind

## Question
Starting from a deployment with `--http-bind` reachable from other pods in the cluster, can an attacker who gets the sync to conclude `hash == git.ref` when the ref is not actually a pinned hash (ref name equal to a hash, peeled tag) drive the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping to a state where sleepForever() is entered and the sidecar never syncs again for the container's lifetime, defeating “the terminal 'pinned hash' state is only reached for a genuinely pinned hash” and causing permanent denial of updates, including security updates, to the consumer?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Gets the sync to conclude `hash == git.ref` when the ref is not actually a pinned hash (ref name equal to a hash, peeled tag). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: sleepForever() is entered and the sidecar never syncs again for the container's lifetime
- Invariant to test: the terminal 'pinned hash' state is only reached for a genuinely pinned hash
- Expected Immunefi impact: permanent denial of updates, including security updates, to the consumer (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: curl the bound port from an unauthorized context and assert nothing sensitive (argv, profiles, counters) is returned
