# Q5882: repoSync.removeStaleWorktrees — hardlink cross worktree under gc always

## Question
Can an unprivileged attacker who commits content that makes git share objects/hardlinks across worktrees so deleting one damages another, under `--git-gc=always`, reach a state where — in removeStaleWorktrees(): the mtime-vs-staleTimeout predicate that must never delete the current worktree — reclaiming a stale worktree corrupts the live one, breaking the invariant that worktrees are independently deletable and yielding corruption of published content mid-service?

## Target
- File/function: [main.go](main.go) — `repoSync.removeStaleWorktrees`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Commits content that makes git share objects/hardlinks across worktrees so deleting one damages another. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: reclaiming a stale worktree corrupts the live one
- Invariant to test: worktrees are independently deletable
- Expected Immunefi impact: corruption of published content mid-service (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: force the failure condition and assert git-sync recovers without wiping already-published data
