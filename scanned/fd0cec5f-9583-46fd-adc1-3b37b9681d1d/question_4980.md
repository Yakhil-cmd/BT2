# Q4980: repoSync.currentWorktree — consumer toctou under shared volume

## Question
Starting from a shared volume readable and traversable by a co-tenant container, can an attacker who publishes rapidly while the consumer walks the tree behind the link drive currentWorktree(): `os.Readlink(link)` and the absolute-vs-relative target interpretation to a state where the old worktree is removed by cleanup while the consumer is mid-read through the link it already resolved, defeating “a published worktree survives long enough for in-flight readers” and causing consumer crashes / partial reads: workload outage?

## Target
- File/function: [main.go](main.go) — `repoSync.currentWorktree`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Publishes rapidly while the consumer walks the tree behind the link. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the old worktree is removed by cleanup while the consumer is mid-read through the link it already resolved
- Invariant to test: a published worktree survives long enough for in-flight readers
- Expected Immunefi impact: consumer crashes / partial reads: workload outage (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: loop a reader on the link while syncing rapidly and assert it never observes a dangling or `tmp-link` path
