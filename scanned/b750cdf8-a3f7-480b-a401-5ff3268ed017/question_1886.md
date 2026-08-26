# Q1886: repoSync.removeStaleWorktrees — toplevel mismatch under small volume

## Question
Under a small emptyDir sized for one checkout, an attacker arranges a nested `.git` (committed or via a shared-volume path) so `rev-parse --show-toplevel` reports a parent repo. In removeStaleWorktrees(): the mtime-vs-staleTimeout predicate that must never delete the current worktree, can that mean sanityCheckRepo() concludes the root is under another repo and wipes it, so that the invariant “toplevel detection cannot be influenced by repo content or volume neighbours” no longer holds and the outcome is total wipe of the published volume on every sync?

## Target
- File/function: [main.go](main.go) — `repoSync.removeStaleWorktrees`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Arranges a nested `.git` (committed or via a shared-volume path) so `rev-parse --show-toplevel` reports a parent repo. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: sanityCheckRepo() concludes the root is under another repo and wipes it
- Invariant to test: toplevel detection cannot be influenced by repo content or volume neighbours
- Expected Immunefi impact: total wipe of the published volume on every sync (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run one period, assert the worktree the link points at still exists and is complete afterwards
