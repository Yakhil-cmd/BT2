# Q3533: repoSync.cleanup — cleanup early return under short period

## Question
Does cleanup(): removeStaleWorktrees(), `worktree prune`, `reflog expire --expire-unreachable=all --all`, and the `gc` invocation stay safe when an attacker keeps the stale count at zero (all worktrees young) so cleanup() returns before pruning, expiring, or gc'ing in a `--period` shorter than a full cleanup cycle — or can objects and administrative state accumulate without bound while cleanup reports success, violating “maintenance runs regardless of how many worktrees were reclaimed” and producing unbounded volume growth: node disk pressure?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Keeps the stale count at zero (all worktrees young) so cleanup() returns before pruning, expiring, or gc'ing. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: objects and administrative state accumulate without bound while cleanup reports success
- Invariant to test: maintenance runs regardless of how many worktrees were reclaimed
- Expected Immunefi impact: unbounded volume growth: node disk pressure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run several periods against the fixture and assert --root file count and byte size stay bounded
