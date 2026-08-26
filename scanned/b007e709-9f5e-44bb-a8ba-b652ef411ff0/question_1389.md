# Q1389: repoSync.worktreeFor — rel path traversal under subpath mount

## Question
Can an unprivileged attacker who chooses repo/link geometry so `filepath.Rel(linkDir, targetPath)` yields a `../..`-heavy relative target, under a consumer that mounts a subPath of the shared volume rather than the whole volume, reach a state where — in worktreeFor()/worktree.Hash(), which derive identity from the leaf name of `.worktrees/<hash>` — the published relative symlink escapes the volume when the volume is mounted at a different path in the consumer, breaking the invariant that the relative link resolves to the same worktree in every mount namespace and yielding consumer resolving the link to an unintended directory inside its own filesystem?

## Target
- File/function: [main.go](main.go) — `repoSync.worktreeFor / worktree.Hash`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Chooses repo/link geometry so `filepath.Rel(linkDir, targetPath)` yields a `../..`-heavy relative target. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the published relative symlink escapes the volume when the volume is mounted at a different path in the consumer
- Invariant to test: the relative link resolves to the same worktree in every mount namespace
- Expected Immunefi impact: consumer resolving the link to an unintended directory inside its own filesystem (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert every path git-sync creates under the link directory is owned by git-sync and not writable by other UIDs
