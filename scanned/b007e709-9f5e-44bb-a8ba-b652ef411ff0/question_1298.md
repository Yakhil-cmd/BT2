# Q1298: repoSync.createWorktree — sparse checkout poison under default flags

## Question
Can an unprivileged attacker who commits paths chosen to interact with the operator's --sparse-checkout-file patterns (leading `!`, `/`, and glob edge cases), under a default deployment (no sparse checkout, submodules recursive by default), reach a state where — in createWorktree() and its `worktree add --force --detach <path> <hash> --no-checkout` — files the operator intended to exclude are materialised, or intended files are silently dropped from the publish, breaking the invariant that the published tree is exactly the sparse pattern applied to the requested hash and yielding consumers served unintended files (secrets/config) or missing security-relevant files?

## Target
- File/function: [main.go](main.go) — `repoSync.createWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits paths chosen to interact with the operator's --sparse-checkout-file patterns (leading `!`, `/`, and glob edge cases). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: files the operator intended to exclude are materialised, or intended files are silently dropped from the publish
- Invariant to test: the published tree is exactly the sparse pattern applied to the requested hash
- Expected Immunefi impact: consumers served unintended files (secrets/config) or missing security-relevant files (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert the worktree tree hash equals `git ls-tree -r <hash>` from the server
