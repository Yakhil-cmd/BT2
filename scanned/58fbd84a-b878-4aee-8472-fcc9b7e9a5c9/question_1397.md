# Q1397: repoSync.removeWorktree — sparse checkout poison under group write

## Question
Under a deployment using `--group-write`, where the umask is 0002 and the volume is shared with a non-root consumer, an attacker commits paths chosen to interact with the operator's --sparse-checkout-file patterns (leading `!`, `/`, and glob edge cases). In removeWorktree() (`os.RemoveAll` then `worktree prune --verbose`), can that mean files the operator intended to exclude are materialised, or intended files are silently dropped from the publish, so that the invariant “the published tree is exactly the sparse pattern applied to the requested hash” no longer holds and the outcome is consumers served unintended files (secrets/config) or missing security-relevant files?

## Target
- File/function: [main.go](main.go) — `repoSync.removeWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits paths chosen to interact with the operator's --sparse-checkout-file patterns (leading `!`, `/`, and glob edge cases). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: files the operator intended to exclude are materialised, or intended files are silently dropped from the publish
- Invariant to test: the published tree is exactly the sparse pattern applied to the requested hash
- Expected Immunefi impact: consumers served unintended files (secrets/config) or missing security-relevant files (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: build the malicious commit locally, sync once, then assert nothing was created or modified outside --root (`find / -newer` on a scratch container)
