# Q0230: repoSync.removeStaleWorktrees — current worktree deleted under shared volume

## Question
Starting from a shared volume that a co-tenant container can also write into, can an attacker who engineers a hash whose leaf name differs from what currentWorktree().Hash() returns (via link target shape or a non-commit id) drive removeStaleWorktrees(): the mtime-vs-staleTimeout predicate that must never delete the current worktree to a state where the 'never delete the current worktree' predicate misses and the live published tree is deleted, defeating “the worktree the link points at is never deleted” and causing consumers hitting a dangling link: workload outage?

## Target
- File/function: [main.go](main.go) — `repoSync.removeStaleWorktrees`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Engineers a hash whose leaf name differs from what currentWorktree().Hash() returns (via link target shape or a non-commit id). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the 'never delete the current worktree' predicate misses and the live published tree is deleted
- Invariant to test: the worktree the link points at is never deleted
- Expected Immunefi impact: consumers hitting a dangling link: workload outage (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run one period, assert the worktree the link points at still exists and is complete afterwards
