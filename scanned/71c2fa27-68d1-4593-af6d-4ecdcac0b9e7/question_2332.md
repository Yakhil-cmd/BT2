# Q2332: repoSync.initRepo — shallow lock residue under depth1

## Question
Starting from a deployment using `--depth=1` (the documented shallow default for large repos), can an attacker who aborts a shallow fetch mid-flight repeatedly (huge tree pushed then connection reset) so `.git/shallow.lock` survives drive the repo bootstrap in initRepo() (`git init -b git-sync`, `remote get-url/add/set-url origin`) to a state where hasGitLockFile() makes sanityCheckRepo() fail forever, so initRepo() wipes the whole root every cycle and re-clones, defeating “a crashed prior fetch is recovered without destroying and refetching the entire repo on every period” and causing permanent resync loop: volume and network exhaustion, sustained unavailability of fresh data?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Aborts a shallow fetch mid-flight repeatedly (huge tree pushed then connection reset) so `.git/shallow.lock` survives. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: hasGitLockFile() makes sanityCheckRepo() fail forever, so initRepo() wipes the whole root every cycle and re-clones
- Invariant to test: a crashed prior fetch is recovered without destroying and refetching the entire repo on every period
- Expected Immunefi impact: permanent resync loop: volume and network exhaustion, sustained unavailability of fresh data (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
