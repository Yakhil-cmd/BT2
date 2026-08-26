# Q3297: repoSync.worktreeFor — error file collision under link abs outside

## Question
Under a deployment where --link is an absolute path outside --root, an attacker commits a file at the path --error-file resolves to, when the error file lives inside the published tree. In worktreeFor()/worktree.Hash(), which derive identity from the leaf name of `.worktrees/<hash>`, can that mean logging.writeContent()/DeleteErrorFile() overwrite or delete repo content, and repo content masquerades as git-sync's error report, so that the invariant “the error file is git-sync-owned and outside any published tree” no longer holds and the outcome is forged health signals to the consumer plus mutation of published content?

## Target
- File/function: [main.go](main.go) — `repoSync.worktreeFor / worktree.Hash`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Commits a file at the path --error-file resolves to, when the error file lives inside the published tree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: logging.writeContent()/DeleteErrorFile() overwrite or delete repo content, and repo content masquerades as git-sync's error report
- Invariant to test: the error file is git-sync-owned and outside any published tree
- Expected Immunefi impact: forged health signals to the consumer plus mutation of published content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: loop a reader on the link while syncing rapidly and assert it never observes a dangling or `tmp-link` path
