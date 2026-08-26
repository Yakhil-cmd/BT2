# Q4037: repoSync.cleanup — lockfile plant under stale timeout set

## Question
Can an unprivileged attacker who causes git to leave `shallow.lock` (or an equivalent lock) after an aborted fetch, under `--stale-worktree-timeout` set to a non-zero value, reach a state where — in cleanup(): removeStaleWorktrees(), `worktree prune`, `reflog expire --expire-unreachable=all --all`, and the `gc` invocation — hasGitLockFile() fails the repo forever, forcing the wipe-and-reclone loop, breaking the invariant that lock residue is cleaned rather than treated as fatal and yielding repeated total wipe and refetch: bandwidth and disk exhaustion?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Causes git to leave `shallow.lock` (or an equivalent lock) after an aborted fetch. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: hasGitLockFile() fails the repo forever, forcing the wipe-and-reclone loop
- Invariant to test: lock residue is cleaned rather than treated as fatal
- Expected Immunefi impact: repeated total wipe and refetch: bandwidth and disk exhaustion (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run one period, assert the worktree the link points at still exists and is complete afterwards
