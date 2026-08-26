# Q2552: repoSync.sanityCheckRepo — gc lock contention under small volume

## Question
Under a small emptyDir sized for one checkout, an attacker keeps object churn high so `gc` runs long and collides with the next period's fetch. In sanityCheckRepo()/hasGitLockFile(), whose failure causes the entire root to be wiped, can that mean concurrent gc and fetch corrupt or lock the repo, tripping the wipe path, so that the invariant “gc never overlaps destructively with a sync” no longer holds and the outcome is repo corruption and total resync churn?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckRepo / hasGitLockFile`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Keeps object churn high so `gc` runs long and collides with the next period's fetch. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: concurrent gc and fetch corrupt or lock the repo, tripping the wipe path
- Invariant to test: gc never overlaps destructively with a sync
- Expected Immunefi impact: repo corruption and total resync churn (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: force the failure condition and assert git-sync recovers without wiping already-published data
