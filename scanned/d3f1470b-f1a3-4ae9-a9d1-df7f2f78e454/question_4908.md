# Q4908: repoSync.currentWorktree — consumer toctou under link abs outside

## Question
Under a deployment where --link is an absolute path outside --root, an attacker publishes rapidly while the consumer walks the tree behind the link. In currentWorktree(): `os.Readlink(link)` and the absolute-vs-relative target interpretation, can that mean the old worktree is removed by cleanup while the consumer is mid-read through the link it already resolved, so that the invariant “a published worktree survives long enough for in-flight readers” no longer holds and the outcome is consumer crashes / partial reads: workload outage?

## Target
- File/function: [main.go](main.go) — `repoSync.currentWorktree`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Publishes rapidly while the consumer walks the tree behind the link. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the old worktree is removed by cleanup while the consumer is mid-read through the link it already resolved
- Invariant to test: a published worktree survives long enough for in-flight readers
- Expected Immunefi impact: consumer crashes / partial reads: workload outage (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert every path git-sync creates under the link directory is owned by git-sync and not writable by other UIDs
