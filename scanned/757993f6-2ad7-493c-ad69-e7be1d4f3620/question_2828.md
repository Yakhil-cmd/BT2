# Q2828: repoSync.sanityCheckWorktree — fsck blind spot under short sync timeout

## Question
Can an unprivileged attacker who commits objects that pass `fsck --connectivity-only` but are semantically broken (bad modes, duplicate tree entries, `.` / `..` names), under a tight `--sync-timeout` relative to repo size, reach a state where — in sanityCheckWorktree() (`dirIsEmpty`, `rev-parse HEAD`, `fsck --connectivity-only`) — sanityCheckWorktree() reports healthy while the checked-out tree is not what the hash claims, breaking the invariant that sanity checks reject any tree that cannot be safely materialised and yielding malformed tree published as verified content?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits objects that pass `fsck --connectivity-only` but are semantically broken (bad modes, duplicate tree entries, `.` / `..` names). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: sanityCheckWorktree() reports healthy while the checked-out tree is not what the hash claims
- Invariant to test: sanity checks reject any tree that cannot be safely materialised
- Expected Immunefi impact: malformed tree published as verified content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert the worktree tree hash equals `git ls-tree -r <hash>` from the server
