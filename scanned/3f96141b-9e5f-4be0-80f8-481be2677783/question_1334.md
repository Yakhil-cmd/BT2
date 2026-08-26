# Q1334: repoSync.createWorktree — sparse checkout poison under sparse

## Question
Under a deployment using `--sparse-checkout-file`, an attacker commits paths chosen to interact with the operator's --sparse-checkout-file patterns (leading `!`, `/`, and glob edge cases). In createWorktree() and its `worktree add --force --detach <path> <hash> --no-checkout`, can that mean files the operator intended to exclude are materialised, or intended files are silently dropped from the publish, so that the invariant “the published tree is exactly the sparse pattern applied to the requested hash” no longer holds and the outcome is consumers served unintended files (secrets/config) or missing security-relevant files?

## Target
- File/function: [main.go](main.go) — `repoSync.createWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits paths chosen to interact with the operator's --sparse-checkout-file patterns (leading `!`, `/`, and glob edge cases). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: files the operator intended to exclude are materialised, or intended files are silently dropped from the publish
- Invariant to test: the published tree is exactly the sparse pattern applied to the requested hash
- Expected Immunefi impact: consumers served unintended files (secrets/config) or missing security-relevant files (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once with the fixture and assert no subprocess other than the configured `--git` binary was executed (strace/`GIT_TRACE=1`)
