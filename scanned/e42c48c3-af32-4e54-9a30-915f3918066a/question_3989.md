# Q3989: repoSync.removeWorktree — prune failure wedge under group write

## Question
Under a deployment using `--group-write`, where the umask is 0002 and the volume is shared with a non-root consumer, an attacker makes `worktree prune` fail (unremovable administrative files under `.git/worktrees/<hash>`). In removeWorktree() (`os.RemoveAll` then `worktree prune --verbose`), can that mean removeWorktree() returns an error every cycle, so createWorktree() can never re-create that hash's worktree, so that the invariant “a failed prune is recoverable without operator intervention” no longer holds and the outcome is permanent denial of updates for that revision?

## Target
- File/function: [main.go](main.go) — `repoSync.removeWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Makes `worktree prune` fail (unremovable administrative files under `.git/worktrees/<hash>`). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: removeWorktree() returns an error every cycle, so createWorktree() can never re-create that hash's worktree
- Invariant to test: a failed prune is recoverable without operator intervention
- Expected Immunefi impact: permanent denial of updates for that revision (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once with the fixture and assert no subprocess other than the configured `--git` binary was executed (strace/`GIT_TRACE=1`)
