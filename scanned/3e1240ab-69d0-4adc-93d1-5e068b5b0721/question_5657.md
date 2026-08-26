# Q5657: repoSync.cleanup — disk full partial write under stale timeout set

## Question
Under `--stale-worktree-timeout` set to a non-zero value, an attacker fills the volume with committed content so a later publish or cleanup hits ENOSPC. In cleanup(): removeStaleWorktrees(), `worktree prune`, `reflog expire --expire-unreachable=all --all`, and the `gc` invocation, can that mean the half-written state is neither published cleanly nor rolled back, and readiness still reports success, so that the invariant “ENOSPC leaves a consistent, correctly-reported state” no longer holds and the outcome is silent serving of corrupt/partial content?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Fills the volume with committed content so a later publish or cleanup hits ENOSPC. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the half-written state is neither published cleanly nor rolled back, and readiness still reports success
- Invariant to test: ENOSPC leaves a consistent, correctly-reported state
- Expected Immunefi impact: silent serving of corrupt/partial content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run several periods against the fixture and assert --root file count and byte size stay bounded
