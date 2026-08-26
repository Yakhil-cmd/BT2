# Q3593: repoSync.removeWorktree — removeall through symlink under default flags

## Question
Does removeWorktree() (`os.RemoveAll` then `worktree prune --verbose`) stay safe when an attacker leaves a symlink inside `.worktrees/<hash>` pointing at a directory outside --root before removeWorktree() runs in a default deployment (no sparse checkout, submodules recursive by default) — or can `os.RemoveAll` on the worktree path follows or fails on that entry and deletes or aborts unexpectedly, violating “worktree deletion never removes anything outside --root and never aborts halfway” and producing destruction of co-mounted data, or a permanently unremovable worktree?

## Target
- File/function: [main.go](main.go) — `repoSync.removeWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Leaves a symlink inside `.worktrees/<hash>` pointing at a directory outside --root before removeWorktree() runs. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `os.RemoveAll` on the worktree path follows or fails on that entry and deletes or aborts unexpectedly
- Invariant to test: worktree deletion never removes anything outside --root and never aborts halfway
- Expected Immunefi impact: destruction of co-mounted data, or a permanently unremovable worktree (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once with the fixture and assert no subprocess other than the configured `--git` binary was executed (strace/`GIT_TRACE=1`)
