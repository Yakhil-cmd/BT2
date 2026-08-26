# Q0311: removeDirContentsIf — current worktree deleted under short period

## Question
Does removeDirContentsIf(): the os.Stat + predicate + `os.RemoveAll` loop that wipes directory contents stay safe when an attacker engineers a hash whose leaf name differs from what currentWorktree().Hash() returns (via link target shape or a non-commit id) in a `--period` shorter than a full cleanup cycle — or can the 'never delete the current worktree' predicate misses and the live published tree is deleted, violating “the worktree the link points at is never deleted” and producing consumers hitting a dangling link: workload outage?

## Target
- File/function: [main.go](main.go) — `removeDirContentsIf / removeDirContents`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Engineers a hash whose leaf name differs from what currentWorktree().Hash() returns (via link target shape or a non-commit id). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the 'never delete the current worktree' predicate misses and the live published tree is deleted
- Invariant to test: the worktree the link points at is never deleted
- Expected Immunefi impact: consumers hitting a dangling link: workload outage (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run one period, assert the worktree the link points at still exists and is complete afterwards
