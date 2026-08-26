# Q0309: repoSync.worktreeFor — link inside tree under error file

## Question
Does worktreeFor()/worktree.Hash(), which derive identity from the leaf name of `.worktrees/<hash>` stay safe when an attacker commits a file or directory at the repo path that --link resolves to when --link is relative to --root in a deployment using `--error-file` inside --root — or can the checked-out entry and the published symlink contend for one path, so the link ends up pointing at attacker-committed content instead of a worktree, violating “the --link path is owned exclusively by git-sync and never by repo content” and producing consumers loading attacker-chosen files through the documented link contract?

## Target
- File/function: [main.go](main.go) — `repoSync.worktreeFor / worktree.Hash`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Commits a file or directory at the repo path that --link resolves to when --link is relative to --root. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the checked-out entry and the published symlink contend for one path, so the link ends up pointing at attacker-committed content instead of a worktree
- Invariant to test: the --link path is owned exclusively by git-sync and never by repo content
- Expected Immunefi impact: consumers loading attacker-chosen files through the documented link contract (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: loop a reader on the link while syncing rapidly and assert it never observes a dangling or `tmp-link` path
