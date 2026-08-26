# Q5061: repoSync.worktreeFor — consumer toctou under short period

## Question
Does worktreeFor()/worktree.Hash(), which derive identity from the leaf name of `.worktrees/<hash>` stay safe when an attacker publishes rapidly while the consumer walks the tree behind the link in a sub-second-to-seconds `--period`, so publishes are frequent — or can the old worktree is removed by cleanup while the consumer is mid-read through the link it already resolved, violating “a published worktree survives long enough for in-flight readers” and producing consumer crashes / partial reads: workload outage?

## Target
- File/function: [main.go](main.go) — `repoSync.worktreeFor / worktree.Hash`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Publishes rapidly while the consumer walks the tree behind the link. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the old worktree is removed by cleanup while the consumer is mid-read through the link it already resolved
- Invariant to test: a published worktree survives long enough for in-flight readers
- Expected Immunefi impact: consumer crashes / partial reads: workload outage (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: loop a reader on the link while syncing rapidly and assert it never observes a dangling or `tmp-link` path
