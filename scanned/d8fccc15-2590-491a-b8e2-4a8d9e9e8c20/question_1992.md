# Q1992: repoSync.currentWorktree — publish before materialise under link abs outside

## Question
Can an unprivileged attacker who makes submodule or LFS materialisation lag the superproject checkout, under a deployment where --link is an absolute path outside --root, reach a state where — in currentWorktree(): `os.Readlink(link)` and the absolute-vs-relative target interpretation — the link is swapped to a worktree whose content is still being written, breaking the invariant that publish happens strictly after the worktree is complete and yielding consumers executing a partially populated tree?

## Target
- File/function: [main.go](main.go) — `repoSync.currentWorktree`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Makes submodule or LFS materialisation lag the superproject checkout. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the link is swapped to a worktree whose content is still being written
- Invariant to test: publish happens strictly after the worktree is complete
- Expected Immunefi impact: consumers executing a partially populated tree (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert every path git-sync creates under the link directory is owned by git-sync and not writable by other UIDs
