# Q2748: repoSync.currentWorktree — stale link after wipe under group write

## Question
Under `--group-write` enabled, so the umask is 0002, an attacker forces the root wipe path in initRepo() while the link is live. In currentWorktree(): `os.Readlink(link)` and the absolute-vs-relative target interpretation, can that mean removeDirContents() deletes the worktree but the link, or a copy of it, survives pointing at nothing, so that the invariant “the link and its target are removed and restored atomically” no longer holds and the outcome is dangling link served to consumers: workload outage?

## Target
- File/function: [main.go](main.go) — `repoSync.currentWorktree`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Forces the root wipe path in initRepo() while the link is live. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: removeDirContents() deletes the worktree but the link, or a copy of it, survives pointing at nothing
- Invariant to test: the link and its target are removed and restored atomically
- Expected Immunefi impact: dangling link served to consumers: workload outage (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: loop a reader on the link while syncing rapidly and assert it never observes a dangling or `tmp-link` path
