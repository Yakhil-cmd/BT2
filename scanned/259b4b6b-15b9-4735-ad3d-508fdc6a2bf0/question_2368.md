# Q2368: repoSync.initRepo — shallow lock residue under nodepth after depth

## Question
Can an unprivileged attacker who aborts a shallow fetch mid-flight repeatedly (huge tree pushed then connection reset) so `.git/shallow.lock` survives, under a deployment where --depth was previously set and is now 0, so the --unshallow path is live, reach a state where — in the repo bootstrap in initRepo() (`git init -b git-sync`, `remote get-url/add/set-url origin`) — hasGitLockFile() makes sanityCheckRepo() fail forever, so initRepo() wipes the whole root every cycle and re-clones, breaking the invariant that a crashed prior fetch is recovered without destroying and refetching the entire repo on every period and yielding permanent resync loop: volume and network exhaustion, sustained unavailability of fresh data?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Aborts a shallow fetch mid-flight repeatedly (huge tree pushed then connection reset) so `.git/shallow.lock` survives. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: hasGitLockFile() makes sanityCheckRepo() fail forever, so initRepo() wipes the whole root every cycle and re-clones
- Invariant to test: a crashed prior fetch is recovered without destroying and refetching the entire repo on every period
- Expected Immunefi impact: permanent resync loop: volume and network exhaustion, sustained unavailability of fresh data (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: stand up a local bare repo (file:// or `git daemon`), reproduce the ref/object shape, run git-sync for two periods and diff `readlink <link>` against the ref's real tip
