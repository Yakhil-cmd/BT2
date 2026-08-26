# Q2487: repoSync.publishSymlink — link dir mkdirall under stale timeout

## Question
Under `--stale-worktree-timeout` set, so previous worktrees linger, an attacker commits a symlink at the parent path of --link so `os.MkdirAll(linkDir)` follows it. In publishSymlink(): the `tmp-link` symlink plus `os.Rename` swap and the `filepath.Rel(linkDir, target)` computation, can that mean the link directory is created outside --root and the publish writes there, so that the invariant “link-directory creation never follows repo-controlled symlinks” no longer holds and the outcome is arbitrary directory/symlink creation outside --root?

## Target
- File/function: [main.go](main.go) — `repoSync.publishSymlink`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Commits a symlink at the parent path of --link so `os.MkdirAll(linkDir)` follows it. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the link directory is created outside --root and the publish writes there
- Invariant to test: link-directory creation never follows repo-controlled symlinks
- Expected Immunefi impact: arbitrary directory/symlink creation outside --root (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: loop a reader on the link while syncing rapidly and assert it never observes a dangling or `tmp-link` path
