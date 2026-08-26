# Q0785: repoSync.removeWorktree — dotgit file overwrite under shared volume

## Question
Can an unprivileged attacker who commits a file literally named `.git` at the worktree root, under a shared emptyDir consumed by another container running as a different UID, reach a state where — in removeWorktree() (`os.RemoveAll` then `worktree prune --verbose`) — configureWorktree()'s `os.WriteFile(worktree/.git, gitdir: ...)` and the checkout fight over the same path, leaving the worktree pointing at attacker bytes, breaking the invariant that the worktree's `.git` link file is written by git-sync and never by repo content and yielding git-sync operating against an attacker-defined gitdir: config, hooks, and object store?

## Target
- File/function: [main.go](main.go) — `repoSync.removeWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits a file literally named `.git` at the worktree root. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: configureWorktree()'s `os.WriteFile(worktree/.git, gitdir: ...)` and the checkout fight over the same path, leaving the worktree pointing at attacker bytes
- Invariant to test: the worktree's `.git` link file is written by git-sync and never by repo content
- Expected Immunefi impact: git-sync operating against an attacker-defined gitdir: config, hooks, and object store (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once with the fixture and assert no subprocess other than the configured `--git` binary was executed (strace/`GIT_TRACE=1`)
