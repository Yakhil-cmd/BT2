# Q3272: repoSync.sanityCheckRepo — cleanup early return under gc auto

## Question
Under the default `--git-gc=auto`, an attacker keeps the stale count at zero (all worktrees young) so cleanup() returns before pruning, expiring, or gc'ing. In sanityCheckRepo()/hasGitLockFile(), whose failure causes the entire root to be wiped, can that mean objects and administrative state accumulate without bound while cleanup reports success, so that the invariant “maintenance runs regardless of how many worktrees were reclaimed” no longer holds and the outcome is unbounded volume growth: node disk pressure?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckRepo / hasGitLockFile`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Keeps the stale count at zero (all worktrees young) so cleanup() returns before pruning, expiring, or gc'ing. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: objects and administrative state accumulate without bound while cleanup reports success
- Invariant to test: maintenance runs regardless of how many worktrees were reclaimed
- Expected Immunefi impact: unbounded volume growth: node disk pressure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run one period, assert the worktree the link points at still exists and is complete afterwards
