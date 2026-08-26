# Q0005: repoSync.cleanup — current worktree deleted under gc auto

## Question
Can an unprivileged attacker who engineers a hash whose leaf name differs from what currentWorktree().Hash() returns (via link target shape or a non-commit id), under the default `--git-gc=auto`, reach a state where — in cleanup(): removeStaleWorktrees(), `worktree prune`, `reflog expire --expire-unreachable=all --all`, and the `gc` invocation — the 'never delete the current worktree' predicate misses and the live published tree is deleted, breaking the invariant that the worktree the link points at is never deleted and yielding consumers hitting a dangling link: workload outage?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Engineers a hash whose leaf name differs from what currentWorktree().Hash() returns (via link target shape or a non-commit id). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the 'never delete the current worktree' predicate misses and the live published tree is deleted
- Invariant to test: the worktree the link points at is never deleted
- Expected Immunefi impact: consumers hitting a dangling link: workload outage (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run several periods against the fixture and assert --root file count and byte size stay bounded
