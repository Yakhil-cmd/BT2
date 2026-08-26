# Q0567: touch — ready before publish under onetime

## Question
Under `--one-time` mode used as an init container, an attacker times a failure between publish and the loop's setRepoReady()/touch-file update. In touch()'s MkdirAll+Chtimes+Create, addUser()'s append to /etc/passwd, and sleepForever()'s terminal state, can that mean readiness and the touch-file disagree with the actual link target, so that the invariant “readiness signals are consistent with the published link” no longer holds and the outcome is orchestration routing traffic to a workload with wrong content?

## Target
- File/function: [main.go](main.go) — `touch / addUser / sleepForever`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Times a failure between publish and the loop's setRepoReady()/touch-file update. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: readiness and the touch-file disagree with the actual link target
- Invariant to test: readiness signals are consistent with the published link
- Expected Immunefi impact: orchestration routing traffic to a workload with wrong content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: break the sync deterministically and assert `/` stops returning 200 (or that the staleness is otherwise surfaced)
