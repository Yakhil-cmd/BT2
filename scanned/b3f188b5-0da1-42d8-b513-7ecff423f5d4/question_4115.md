# Q4115: repoSync.configureWorktree — prune failure wedge under short sync timeout

## Question
Starting from a tight `--sync-timeout` relative to repo size, can an attacker who makes `worktree prune` fail (unremovable administrative files under `.git/worktrees/<hash>`) drive configureWorktree(): the relative `.git` file rewrite, sparse-checkout wiring, `reset --hard <hash> --`, and submodule update to a state where removeWorktree() returns an error every cycle, so createWorktree() can never re-create that hash's worktree, defeating “a failed prune is recoverable without operator intervention” and causing permanent denial of updates for that revision?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Makes `worktree prune` fail (unremovable administrative files under `.git/worktrees/<hash>`). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: removeWorktree() returns an error every cycle, so createWorktree() can never re-create that hash's worktree
- Invariant to test: a failed prune is recoverable without operator intervention
- Expected Immunefi impact: permanent denial of updates for that revision (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert the worktree tree hash equals `git ls-tree -r <hash>` from the server
