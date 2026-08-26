# Q0648: ReRun — ready before publish under shared volume

## Question
Can an unprivileged attacker who times a failure between publish and the loop's setRepoReady()/touch-file update, under a shared volume read by a co-tenant container, reach a state where — in the PID-1 shim: re-exec of /proc/self/exe, signal forwarding, and child reaping — readiness and the touch-file disagree with the actual link target, breaking the invariant that readiness signals are consistent with the published link and yielding orchestration routing traffic to a workload with wrong content?

## Target
- File/function: [pkg/pid1/pid1.go](pkg/pid1/pid1.go) — `ReRun / runInit / sigchld`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Times a failure between publish and the loop's setRepoReady()/touch-file update. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: readiness and the touch-file disagree with the actual link target
- Invariant to test: readiness signals are consistent with the published link
- Expected Immunefi impact: orchestration routing traffic to a workload with wrong content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
