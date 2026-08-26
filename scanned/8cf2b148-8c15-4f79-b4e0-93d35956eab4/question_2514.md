# Q2514: absPath.Join — link dir mkdirall under stale timeout

## Question
Can an unprivileged attacker who commits a symlink at the parent path of --link so `os.MkdirAll(linkDir)` follows it, under `--stale-worktree-timeout` set, so previous worktrees linger, reach a state where — in absPath.Join()/Split()/Canonical(), which clean paths without verifying containment in --root — the link directory is created outside --root and the publish writes there, breaking the invariant that link-directory creation never follows repo-controlled symlinks and yielding arbitrary directory/symlink creation outside --root?

## Target
- File/function: [abspath.go](abspath.go) — `absPath.Join / Split / Canonical`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Commits a symlink at the parent path of --link so `os.MkdirAll(linkDir)` follows it. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the link directory is created outside --root and the publish writes there
- Invariant to test: link-directory creation never follows repo-controlled symlinks
- Expected Immunefi impact: arbitrary directory/symlink creation outside --root (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: loop a reader on the link while syncing rapidly and assert it never observes a dangling or `tmp-link` path
