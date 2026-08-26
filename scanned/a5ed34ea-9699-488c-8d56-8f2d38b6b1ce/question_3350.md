# Q3350: repoSync.createWorktree — hardlink and mode bits under shared volume

## Question
Under a shared emptyDir consumed by another container running as a different UID, an attacker commits files with setgid/sticky-adjacent modes, or many hardlink-shaped duplicates. In createWorktree() and its `worktree add --force --detach <path> <hash> --no-checkout`, can that mean checked-out permissions combined with the --group-write umask make published files writable by a co-tenant, so that the invariant “published files are never writable by processes outside git-sync” no longer holds and the outcome is co-tenant tampering with published code before the consumer reads it?

## Target
- File/function: [main.go](main.go) — `repoSync.createWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits files with setgid/sticky-adjacent modes, or many hardlink-shaped duplicates. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: checked-out permissions combined with the --group-write umask make published files writable by a co-tenant
- Invariant to test: published files are never writable by processes outside git-sync
- Expected Immunefi impact: co-tenant tampering with published code before the consumer reads it (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert the worktree tree hash equals `git ls-tree -r <hash>` from the server
