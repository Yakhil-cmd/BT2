# Q2570: repoSync.removeStaleWorktrees — gc lock contention under short period

## Question
Can an unprivileged attacker who keeps object churn high so `gc` runs long and collides with the next period's fetch, under a `--period` shorter than a full cleanup cycle, reach a state where — in removeStaleWorktrees(): the mtime-vs-staleTimeout predicate that must never delete the current worktree — concurrent gc and fetch corrupt or lock the repo, tripping the wipe path, breaking the invariant that gc never overlaps destructively with a sync and yielding repo corruption and total resync churn?

## Target
- File/function: [main.go](main.go) — `repoSync.removeStaleWorktrees`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Keeps object churn high so `gc` runs long and collides with the next period's fetch. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: concurrent gc and fetch corrupt or lock the repo, tripping the wipe path
- Invariant to test: gc never overlaps destructively with a sync
- Expected Immunefi impact: repo corruption and total resync churn (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run one period, assert the worktree the link points at still exists and is complete afterwards
