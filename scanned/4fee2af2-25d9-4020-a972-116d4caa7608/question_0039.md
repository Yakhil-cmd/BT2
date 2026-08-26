# Q0039: repoSync.publishSymlink — link inside tree under link abs outside

## Question
Under a deployment where --link is an absolute path outside --root, an attacker commits a file or directory at the repo path that --link resolves to when --link is relative to --root. In publishSymlink(): the `tmp-link` symlink plus `os.Rename` swap and the `filepath.Rel(linkDir, target)` computation, can that mean the checked-out entry and the published symlink contend for one path, so the link ends up pointing at attacker-committed content instead of a worktree, so that the invariant “the --link path is owned exclusively by git-sync and never by repo content” no longer holds and the outcome is consumers loading attacker-chosen files through the documented link contract?

## Target
- File/function: [main.go](main.go) — `repoSync.publishSymlink`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Commits a file or directory at the repo path that --link resolves to when --link is relative to --root. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the checked-out entry and the published symlink contend for one path, so the link ends up pointing at attacker-committed content instead of a worktree
- Invariant to test: the --link path is owned exclusively by git-sync and never by repo content
- Expected Immunefi impact: consumers loading attacker-chosen files through the documented link contract (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: loop a reader on the link while syncing rapidly and assert it never observes a dangling or `tmp-link` path
