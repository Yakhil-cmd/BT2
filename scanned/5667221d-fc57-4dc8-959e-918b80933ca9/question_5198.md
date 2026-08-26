# Q5198: repoSync.removeStaleWorktrees — reflog expire cost under gc auto

## Question
Under the default `--git-gc=auto`, an attacker pushes enough refs to make `reflog expire --all` take longer than the period. In removeStaleWorktrees(): the mtime-vs-staleTimeout predicate that must never delete the current worktree, can that mean cleanup consumes the whole period, starving fetch and publish, so that the invariant “maintenance cannot starve the sync loop” no longer holds and the outcome is permanent denial of updates?

## Target
- File/function: [main.go](main.go) — `repoSync.removeStaleWorktrees`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Pushes enough refs to make `reflog expire --all` take longer than the period. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: cleanup consumes the whole period, starving fetch and publish
- Invariant to test: maintenance cannot starve the sync loop
- Expected Immunefi impact: permanent denial of updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: force the failure condition and assert git-sync recovers without wiping already-published data
