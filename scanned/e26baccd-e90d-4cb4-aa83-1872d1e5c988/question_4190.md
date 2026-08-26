# Q4190: repoSync.removeStaleWorktrees — lockfile plant under short period

## Question
Under a `--period` shorter than a full cleanup cycle, an attacker causes git to leave `shallow.lock` (or an equivalent lock) after an aborted fetch. In removeStaleWorktrees(): the mtime-vs-staleTimeout predicate that must never delete the current worktree, can that mean hasGitLockFile() fails the repo forever, forcing the wipe-and-reclone loop, so that the invariant “lock residue is cleaned rather than treated as fatal” no longer holds and the outcome is repeated total wipe and refetch: bandwidth and disk exhaustion?

## Target
- File/function: [main.go](main.go) — `repoSync.removeStaleWorktrees`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Causes git to leave `shallow.lock` (or an equivalent lock) after an aborted fetch. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: hasGitLockFile() fails the repo forever, forcing the wipe-and-reclone loop
- Invariant to test: lock residue is cleaned rather than treated as fatal
- Expected Immunefi impact: repeated total wipe and refetch: bandwidth and disk exhaustion (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run several periods against the fixture and assert --root file count and byte size stay bounded
