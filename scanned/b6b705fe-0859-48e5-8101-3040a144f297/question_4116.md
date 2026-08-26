# Q4116: repoSync.currentWorktree — readlink empty under stale timeout

## Question
Starting from `--stale-worktree-timeout` set, so previous worktrees linger, can an attacker who leaves the link path as a regular file or a broken entry across a restart on a reused volume drive currentWorktree(): `os.Readlink(link)` and the absolute-vs-relative target interpretation to a state where currentWorktree() returns "" and change detection republishes and re-hooks on every period, defeating “current-state detection distinguishes 'no link' from 'unreadable link'” and causing hook amplification and continuous republish churn?

## Target
- File/function: [main.go](main.go) — `repoSync.currentWorktree`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Leaves the link path as a regular file or a broken entry across a restart on a reused volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: currentWorktree() returns "" and change detection republishes and re-hooks on every period
- Invariant to test: current-state detection distinguishes 'no link' from 'unreadable link'
- Expected Immunefi impact: hook amplification and continuous republish churn (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: loop a reader on the link while syncing rapidly and assert it never observes a dangling or `tmp-link` path
