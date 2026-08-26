# Q2278: repoSync.SyncRepo — shallow lock residue under first sync

## Question
Can an unprivileged attacker who aborts a shallow fetch mid-flight repeatedly (huge tree pushed then connection reset) so `.git/shallow.lock` survives, under the very first sync after container start, when the root is empty and syncCount is 0, reach a state where — in the hash resolution and change-detection logic in SyncRepo() (`rev-parse FETCH_HEAD^{}`, currentHash vs remoteHash, `reset --soft`) — hasGitLockFile() makes sanityCheckRepo() fail forever, so initRepo() wipes the whole root every cycle and re-clones, breaking the invariant that a crashed prior fetch is recovered without destroying and refetching the entire repo on every period and yielding permanent resync loop: volume and network exhaustion, sustained unavailability of fresh data?

## Target
- File/function: [main.go](main.go) — `repoSync.SyncRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Aborts a shallow fetch mid-flight repeatedly (huge tree pushed then connection reset) so `.git/shallow.lock` survives. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: hasGitLockFile() makes sanityCheckRepo() fail forever, so initRepo() wipes the whole root every cycle and re-clones
- Invariant to test: a crashed prior fetch is recovered without destroying and refetching the entire repo on every period
- Expected Immunefi impact: permanent resync loop: volume and network exhaustion, sustained unavailability of fresh data (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
