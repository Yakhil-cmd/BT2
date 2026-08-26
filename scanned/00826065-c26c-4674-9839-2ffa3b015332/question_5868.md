# Q5868: ReRun — passwd append under http bind

## Question
Under a deployment with `--http-bind` reachable from other pods in the cluster, an attacker targets addUser()'s unconditional append to /etc/passwd on a restart loop. In the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping, can that mean repeated appends grow /etc/passwd and can shadow or confuse later user lookups used by SSH, so that the invariant “user registration is idempotent” no longer holds and the outcome is auth path corruption / privilege confusion inside the container?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Targets addUser()'s unconditional append to /etc/passwd on a restart loop. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: repeated appends grow /etc/passwd and can shadow or confuse later user lookups used by SSH
- Invariant to test: user registration is idempotent
- Expected Immunefi impact: auth path corruption / privilege confusion inside the container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
