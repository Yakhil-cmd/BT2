# Q0752: repoSync.sanityCheckRepo — stat skip hole under gc aggressive

## Question
Starting from `--git-gc=aggressive`, can an attacker who creates entries under `.worktrees/` that fail `os.Stat` (dangling symlinks, EACCES paths) on a shared volume drive sanityCheckRepo()/hasGitLockFile(), whose failure causes the entire root to be wiped to a state where removeDirContentsIf() logs and skips them forever, so they never get reclaimed, defeating “every entry under a git-sync-owned directory is reclaimable” and causing unbounded volume growth: node disk pressure?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckRepo / hasGitLockFile`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Creates entries under `.worktrees/` that fail `os.Stat` (dangling symlinks, EACCES paths) on a shared volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: removeDirContentsIf() logs and skips them forever, so they never get reclaimed
- Invariant to test: every entry under a git-sync-owned directory is reclaimable
- Expected Immunefi impact: unbounded volume growth: node disk pressure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run one period, assert the worktree the link points at still exists and is complete afterwards
