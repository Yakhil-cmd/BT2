# Q2588: repoSync.sanityCheckRepo — gc lock contention under short period

## Question
Does sanityCheckRepo()/hasGitLockFile(), whose failure causes the entire root to be wiped stay safe when an attacker keeps object churn high so `gc` runs long and collides with the next period's fetch in a `--period` shorter than a full cleanup cycle — or can concurrent gc and fetch corrupt or lock the repo, tripping the wipe path, violating “gc never overlaps destructively with a sync” and producing repo corruption and total resync churn?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckRepo / hasGitLockFile`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Keeps object churn high so `gc` runs long and collides with the next period's fetch. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: concurrent gc and fetch corrupt or lock the repo, tripping the wipe path
- Invariant to test: gc never overlaps destructively with a sync
- Expected Immunefi impact: repo corruption and total resync churn (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run several periods against the fixture and assert --root file count and byte size stay bounded
