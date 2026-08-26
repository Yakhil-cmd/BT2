# Q2073: repoSync.worktreeFor — publish before materialise under shared volume

## Question
Starting from a shared volume readable and traversable by a co-tenant container, can an attacker who makes submodule or LFS materialisation lag the superproject checkout drive worktreeFor()/worktree.Hash(), which derive identity from the leaf name of `.worktrees/<hash>` to a state where the link is swapped to a worktree whose content is still being written, defeating “publish happens strictly after the worktree is complete” and causing consumers executing a partially populated tree?

## Target
- File/function: [main.go](main.go) — `repoSync.worktreeFor / worktree.Hash`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Makes submodule or LFS materialisation lag the superproject checkout. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the link is swapped to a worktree whose content is still being written
- Invariant to test: publish happens strictly after the worktree is complete
- Expected Immunefi impact: consumers executing a partially populated tree (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert every path git-sync creates under the link directory is owned by git-sync and not writable by other UIDs
