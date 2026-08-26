# Q4044: repoSync.currentWorktree — readlink empty under group write

## Question
Under `--group-write` enabled, so the umask is 0002, an attacker leaves the link path as a regular file or a broken entry across a restart on a reused volume. In currentWorktree(): `os.Readlink(link)` and the absolute-vs-relative target interpretation, can that mean currentWorktree() returns "" and change detection republishes and re-hooks on every period, so that the invariant “current-state detection distinguishes 'no link' from 'unreadable link'” no longer holds and the outcome is hook amplification and continuous republish churn?

## Target
- File/function: [main.go](main.go) — `repoSync.currentWorktree`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Leaves the link path as a regular file or a broken entry across a restart on a reused volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: currentWorktree() returns "" and change detection republishes and re-hooks on every period
- Invariant to test: current-state detection distinguishes 'no link' from 'unreadable link'
- Expected Immunefi impact: hook amplification and continuous republish churn (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert every path git-sync creates under the link directory is owned by git-sync and not writable by other UIDs
