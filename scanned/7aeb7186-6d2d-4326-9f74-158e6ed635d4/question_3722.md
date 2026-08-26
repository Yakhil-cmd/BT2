# Q3722: repoSync.removeStaleWorktrees — worktree admin residue under stale timeout set

## Question
Can an unprivileged attacker who makes `worktree prune` leave `.git/worktrees/<hash>` entries that reference removed paths, under `--stale-worktree-timeout` set to a non-zero value, reach a state where — in removeStaleWorktrees(): the mtime-vs-staleTimeout predicate that must never delete the current worktree — later `worktree add` for the same hash fails, blocking republish of that revision, breaking the invariant that administrative worktree state stays consistent with disk and yielding permanent denial of updates for a given revision?

## Target
- File/function: [main.go](main.go) — `repoSync.removeStaleWorktrees`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Makes `worktree prune` leave `.git/worktrees/<hash>` entries that reference removed paths. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: later `worktree add` for the same hash fails, blocking republish of that revision
- Invariant to test: administrative worktree state stays consistent with disk
- Expected Immunefi impact: permanent denial of updates for a given revision (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run one period, assert the worktree the link points at still exists and is complete afterwards
