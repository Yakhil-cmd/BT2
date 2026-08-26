# Q0302: repoSync.removeStaleWorktrees — current worktree deleted under short period

## Question
Under a `--period` shorter than a full cleanup cycle, an attacker engineers a hash whose leaf name differs from what currentWorktree().Hash() returns (via link target shape or a non-commit id). In removeStaleWorktrees(): the mtime-vs-staleTimeout predicate that must never delete the current worktree, can that mean the 'never delete the current worktree' predicate misses and the live published tree is deleted, so that the invariant “the worktree the link points at is never deleted” no longer holds and the outcome is consumers hitting a dangling link: workload outage?

## Target
- File/function: [main.go](main.go) — `repoSync.removeStaleWorktrees`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Engineers a hash whose leaf name differs from what currentWorktree().Hash() returns (via link target shape or a non-commit id). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the 'never delete the current worktree' predicate misses and the live published tree is deleted
- Invariant to test: the worktree the link points at is never deleted
- Expected Immunefi impact: consumers hitting a dangling link: workload outage (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run several periods against the fixture and assert --root file count and byte size stay bounded
