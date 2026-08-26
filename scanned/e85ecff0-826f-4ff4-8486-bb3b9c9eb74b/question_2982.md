# Q2982: absPath.Join — touch file collision under link abs outside

## Question
Under a deployment where --link is an absolute path outside --root, an attacker commits a file at the path --touch-file resolves to inside the published tree. In absPath.Join()/Split()/Canonical(), which clean paths without verifying containment in --root, can that mean touch() rewrites or creates content inside the published worktree after publish, so that the invariant “git-sync never mutates the contents of a published worktree” no longer holds and the outcome is published tree mutated post-publish, breaking content/hash correspondence?

## Target
- File/function: [abspath.go](abspath.go) — `absPath.Join / Split / Canonical`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Commits a file at the path --touch-file resolves to inside the published tree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: touch() rewrites or creates content inside the published worktree after publish
- Invariant to test: git-sync never mutates the contents of a published worktree
- Expected Immunefi impact: published tree mutated post-publish, breaking content/hash correspondence (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: loop a reader on the link while syncing rapidly and assert it never observes a dangling or `tmp-link` path
