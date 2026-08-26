# Q5745: repoSync.worktreeFor — double publish hash under stale timeout

## Question
Under `--stale-worktree-timeout` set, so previous worktrees linger, an attacker gets two different trees published under the same hash across a wipe-and-resync. In worktreeFor()/worktree.Hash(), which derive identity from the leaf name of `.worktrees/<hash>`, can that mean the contract's hash-leaf identity no longer uniquely identifies content on the volume, so that the invariant “hash leaf uniquely determines published bytes” no longer holds and the outcome is undetected content substitution behind a stable hash?

## Target
- File/function: [main.go](main.go) — `repoSync.worktreeFor / worktree.Hash`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Gets two different trees published under the same hash across a wipe-and-resync. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the contract's hash-leaf identity no longer uniquely identifies content on the volume
- Invariant to test: hash leaf uniquely determines published bytes
- Expected Immunefi impact: undetected content substitution behind a stable hash (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: loop a reader on the link while syncing rapidly and assert it never observes a dangling or `tmp-link` path
