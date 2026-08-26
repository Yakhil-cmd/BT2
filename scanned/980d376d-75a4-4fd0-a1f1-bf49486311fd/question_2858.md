# Q2858: repoSync.removeStaleWorktrees — gc prunes live objects under small volume

## Question
Can an unprivileged attacker who arranges reachability so `reflog expire --expire-unreachable=all` plus gc removes objects backing the published worktree, under a small emptyDir sized for one checkout, reach a state where — in removeStaleWorktrees(): the mtime-vs-staleTimeout predicate that must never delete the current worktree — the published tree loses its backing objects and later checks nuke it, breaking the invariant that objects backing published content are never collected and yielding published data destroyed mid-service?

## Target
- File/function: [main.go](main.go) — `repoSync.removeStaleWorktrees`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Arranges reachability so `reflog expire --expire-unreachable=all` plus gc removes objects backing the published worktree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the published tree loses its backing objects and later checks nuke it
- Invariant to test: objects backing published content are never collected
- Expected Immunefi impact: published data destroyed mid-service (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run one period, assert the worktree the link points at still exists and is complete afterwards
