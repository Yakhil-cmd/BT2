# Q2630: repoSync.createWorktree — fsck blind spot under sparse

## Question
Under a deployment using `--sparse-checkout-file`, an attacker commits objects that pass `fsck --connectivity-only` but are semantically broken (bad modes, duplicate tree entries, `.` / `..` names). In createWorktree() and its `worktree add --force --detach <path> <hash> --no-checkout`, can that mean sanityCheckWorktree() reports healthy while the checked-out tree is not what the hash claims, so that the invariant “sanity checks reject any tree that cannot be safely materialised” no longer holds and the outcome is malformed tree published as verified content?

## Target
- File/function: [main.go](main.go) — `repoSync.createWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits objects that pass `fsck --connectivity-only` but are semantically broken (bad modes, duplicate tree entries, `.` / `..` names). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: sanityCheckWorktree() reports healthy while the checked-out tree is not what the hash claims
- Invariant to test: sanity checks reject any tree that cannot be safely materialised
- Expected Immunefi impact: malformed tree published as verified content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: build the malicious commit locally, sync once, then assert nothing was created or modified outside --root (`find / -newer` on a scratch container)
