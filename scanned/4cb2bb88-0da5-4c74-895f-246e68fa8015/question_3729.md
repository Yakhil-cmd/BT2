# Q3729: repoSync.worktreeFor — link name from repo under group write

## Question
Under `--group-write` enabled, so the umask is 0002, an attacker controls the trailing path component of the repo URL so the defaulted --link name (basename of --repo) collides with a real tree entry. In worktreeFor()/worktree.Hash(), which derive identity from the leaf name of `.worktrees/<hash>`, can that mean the default link name lands on top of committed content, so that the invariant “the default link name cannot be shadowed by repo content” no longer holds and the outcome is consumers reading committed data where a link was expected?

## Target
- File/function: [main.go](main.go) — `repoSync.worktreeFor / worktree.Hash`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Controls the trailing path component of the repo URL so the defaulted --link name (basename of --repo) collides with a real tree entry. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the default link name lands on top of committed content
- Invariant to test: the default link name cannot be shadowed by repo content
- Expected Immunefi impact: consumers reading committed data where a link was expected (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert every path git-sync creates under the link directory is owned by git-sync and not writable by other UIDs
