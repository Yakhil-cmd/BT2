# Q2377: repoSync.fetch — shallow lock residue under onetime

## Question
Does the argv assembled in fetch() (`fetch <repo> <ref> --verbose --no-progress --prune --no-auto-gc` plus --depth/--unshallow/--filter) stay safe when an attacker aborts a shallow fetch mid-flight repeatedly (huge tree pushed then connection reset) so `.git/shallow.lock` survives in `--one-time` mode, where the process must exit with a status after a single sync — or can hasGitLockFile() makes sanityCheckRepo() fail forever, so initRepo() wipes the whole root every cycle and re-clones, violating “a crashed prior fetch is recovered without destroying and refetching the entire repo on every period” and producing permanent resync loop: volume and network exhaustion, sustained unavailability of fresh data?

## Target
- File/function: [main.go](main.go) — `repoSync.fetch`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Aborts a shallow fetch mid-flight repeatedly (huge tree pushed then connection reset) so `.git/shallow.lock` survives. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: hasGitLockFile() makes sanityCheckRepo() fail forever, so initRepo() wipes the whole root every cycle and re-clones
- Invariant to test: a crashed prior fetch is recovered without destroying and refetching the entire repo on every period
- Expected Immunefi impact: permanent resync loop: volume and network exhaustion, sustained unavailability of fresh data (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
