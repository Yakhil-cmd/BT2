# Q2354: repoSync.removeStaleWorktrees — gc lock contention under gc aggressive

## Question
Does removeStaleWorktrees(): the mtime-vs-staleTimeout predicate that must never delete the current worktree stay safe when an attacker keeps object churn high so `gc` runs long and collides with the next period's fetch in `--git-gc=aggressive` — or can concurrent gc and fetch corrupt or lock the repo, tripping the wipe path, violating “gc never overlaps destructively with a sync” and producing repo corruption and total resync churn?

## Target
- File/function: [main.go](main.go) — `repoSync.removeStaleWorktrees`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Keeps object churn high so `gc` runs long and collides with the next period's fetch. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: concurrent gc and fetch corrupt or lock the repo, tripping the wipe path
- Invariant to test: gc never overlaps destructively with a sync
- Expected Immunefi impact: repo corruption and total resync churn (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run one period, assert the worktree the link points at still exists and is complete afterwards
