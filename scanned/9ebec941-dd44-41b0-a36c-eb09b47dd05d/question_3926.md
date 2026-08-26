# Q3926: repoSync.createWorktree — prune failure wedge under sparse

## Question
Under a deployment using `--sparse-checkout-file`, an attacker makes `worktree prune` fail (unremovable administrative files under `.git/worktrees/<hash>`). In createWorktree() and its `worktree add --force --detach <path> <hash> --no-checkout`, can that mean removeWorktree() returns an error every cycle, so createWorktree() can never re-create that hash's worktree, so that the invariant “a failed prune is recoverable without operator intervention” no longer holds and the outcome is permanent denial of updates for that revision?

## Target
- File/function: [main.go](main.go) — `repoSync.createWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Makes `worktree prune` fail (unremovable administrative files under `.git/worktrees/<hash>`). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: removeWorktree() returns an error every cycle, so createWorktree() can never re-create that hash's worktree
- Invariant to test: a failed prune is recoverable without operator intervention
- Expected Immunefi impact: permanent denial of updates for that revision (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert the worktree tree hash equals `git ls-tree -r <hash>` from the server
