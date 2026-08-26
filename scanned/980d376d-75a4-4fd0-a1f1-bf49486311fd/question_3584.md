# Q3584: repoSync.sanityCheckWorktree — removeall through symlink under default flags

## Question
Under a default deployment (no sparse checkout, submodules recursive by default), an attacker leaves a symlink inside `.worktrees/<hash>` pointing at a directory outside --root before removeWorktree() runs. In sanityCheckWorktree() (`dirIsEmpty`, `rev-parse HEAD`, `fsck --connectivity-only`), can that mean `os.RemoveAll` on the worktree path follows or fails on that entry and deletes or aborts unexpectedly, so that the invariant “worktree deletion never removes anything outside --root and never aborts halfway” no longer holds and the outcome is destruction of co-mounted data, or a permanently unremovable worktree?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Leaves a symlink inside `.worktrees/<hash>` pointing at a directory outside --root before removeWorktree() runs. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `os.RemoveAll` on the worktree path follows or fails on that entry and deletes or aborts unexpectedly
- Invariant to test: worktree deletion never removes anything outside --root and never aborts halfway
- Expected Immunefi impact: destruction of co-mounted data, or a permanently unremovable worktree (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert the worktree tree hash equals `git ls-tree -r <hash>` from the server
