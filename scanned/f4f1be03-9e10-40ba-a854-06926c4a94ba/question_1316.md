# Q1316: repoSync.sanityCheckWorktree — sparse checkout poison under default flags

## Question
Does sanityCheckWorktree() (`dirIsEmpty`, `rev-parse HEAD`, `fsck --connectivity-only`) stay safe when an attacker commits paths chosen to interact with the operator's --sparse-checkout-file patterns (leading `!`, `/`, and glob edge cases) in a default deployment (no sparse checkout, submodules recursive by default) — or can files the operator intended to exclude are materialised, or intended files are silently dropped from the publish, violating “the published tree is exactly the sparse pattern applied to the requested hash” and producing consumers served unintended files (secrets/config) or missing security-relevant files?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits paths chosen to interact with the operator's --sparse-checkout-file patterns (leading `!`, `/`, and glob edge cases). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: files the operator intended to exclude are materialised, or intended files are silently dropped from the publish
- Invariant to test: the published tree is exactly the sparse pattern applied to the requested hash
- Expected Immunefi impact: consumers served unintended files (secrets/config) or missing security-relevant files (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: build the malicious commit locally, sync once, then assert nothing was created or modified outside --root (`find / -newer` on a scratch container)
