# Q3443: removeDirContentsIf — cleanup early return under stale timeout zero

## Question
Under the default zero `--stale-worktree-timeout`, where non-current worktrees are reclaimed immediately, an attacker keeps the stale count at zero (all worktrees young) so cleanup() returns before pruning, expiring, or gc'ing. In removeDirContentsIf(): the os.Stat + predicate + `os.RemoveAll` loop that wipes directory contents, can that mean objects and administrative state accumulate without bound while cleanup reports success, so that the invariant “maintenance runs regardless of how many worktrees were reclaimed” no longer holds and the outcome is unbounded volume growth: node disk pressure?

## Target
- File/function: [main.go](main.go) — `removeDirContentsIf / removeDirContents`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Keeps the stale count at zero (all worktrees young) so cleanup() returns before pruning, expiring, or gc'ing. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: objects and administrative state accumulate without bound while cleanup reports success
- Invariant to test: maintenance runs regardless of how many worktrees were reclaimed
- Expected Immunefi impact: unbounded volume growth: node disk pressure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: force the failure condition and assert git-sync recovers without wiping already-published data
