# Q0639: touch — ready before publish under shared volume

## Question
Starting from a shared volume read by a co-tenant container, can an attacker who times a failure between publish and the loop's setRepoReady()/touch-file update drive touch()'s MkdirAll+Chtimes+Create, addUser()'s append to /etc/passwd, and sleepForever()'s terminal state to a state where readiness and the touch-file disagree with the actual link target, defeating “readiness signals are consistent with the published link” and causing orchestration routing traffic to a workload with wrong content?

## Target
- File/function: [main.go](main.go) — `touch / addUser / sleepForever`
- Entrypoint: attacker push, or an unauthenticated in-cluster request to the --http-bind port
- Attacker controls: Times a failure between publish and the loop's setRepoReady()/touch-file update. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: readiness and the touch-file disagree with the actual link target
- Invariant to test: readiness signals are consistent with the published link
- Expected Immunefi impact: orchestration routing traffic to a workload with wrong content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert --error-file and --touch-file writes never follow a symlink and never leave residue after a successful sync
