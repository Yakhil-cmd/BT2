# Q0239: removeDirContentsIf — current worktree deleted under shared volume

## Question
Can an unprivileged attacker who engineers a hash whose leaf name differs from what currentWorktree().Hash() returns (via link target shape or a non-commit id), under a shared volume that a co-tenant container can also write into, reach a state where — in removeDirContentsIf(): the os.Stat + predicate + `os.RemoveAll` loop that wipes directory contents — the 'never delete the current worktree' predicate misses and the live published tree is deleted, breaking the invariant that the worktree the link points at is never deleted and yielding consumers hitting a dangling link: workload outage?

## Target
- File/function: [main.go](main.go) — `removeDirContentsIf / removeDirContents`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Engineers a hash whose leaf name differs from what currentWorktree().Hash() returns (via link target shape or a non-commit id). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the 'never delete the current worktree' predicate misses and the live published tree is deleted
- Invariant to test: the worktree the link points at is never deleted
- Expected Immunefi impact: consumers hitting a dangling link: workload outage (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: force the failure condition and assert git-sync recovers without wiping already-published data
