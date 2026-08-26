# Q1857: repoSync.worktreeFor — rename race under stale timeout

## Question
Under `--stale-worktree-timeout` set, so previous worktrees linger, an attacker drives publishes at high frequency so the consumer reads the link exactly between `os.Symlink` and `os.Rename`. In worktreeFor()/worktree.Hash(), which derive identity from the leaf name of `.worktrees/<hash>`, can that mean the consumer observes the tmp name or a dangling link, defeating the atomic-publish guarantee, so that the invariant “consumers only ever observe a complete, valid link” no longer holds and the outcome is workload outage or partial-tree execution?

## Target
- File/function: [main.go](main.go) — `repoSync.worktreeFor / worktree.Hash`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Drives publishes at high frequency so the consumer reads the link exactly between `os.Symlink` and `os.Rename`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the consumer observes the tmp name or a dangling link, defeating the atomic-publish guarantee
- Invariant to test: consumers only ever observe a complete, valid link
- Expected Immunefi impact: workload outage or partial-tree execution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: loop a reader on the link while syncing rapidly and assert it never observes a dangling or `tmp-link` path
