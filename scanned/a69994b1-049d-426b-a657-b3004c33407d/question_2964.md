# Q2964: repoSync.currentWorktree — touch file collision under link abs outside

## Question
Starting from a deployment where --link is an absolute path outside --root, can an attacker who commits a file at the path --touch-file resolves to inside the published tree drive currentWorktree(): `os.Readlink(link)` and the absolute-vs-relative target interpretation to a state where touch() rewrites or creates content inside the published worktree after publish, defeating “git-sync never mutates the contents of a published worktree” and causing published tree mutated post-publish, breaking content/hash correspondence?

## Target
- File/function: [main.go](main.go) — `repoSync.currentWorktree`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Commits a file at the path --touch-file resolves to inside the published tree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: touch() rewrites or creates content inside the published worktree after publish
- Invariant to test: git-sync never mutates the contents of a published worktree
- Expected Immunefi impact: published tree mutated post-publish, breaking content/hash correspondence (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert every path git-sync creates under the link directory is owned by git-sync and not writable by other UIDs
