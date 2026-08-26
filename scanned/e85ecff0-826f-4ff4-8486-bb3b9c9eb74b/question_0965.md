# Q0965: repoSync.removeWorktree — dotgit file overwrite under crash resume

## Question
Under a resume after the previous process died inside configureWorktree(), an attacker commits a file literally named `.git` at the worktree root. In removeWorktree() (`os.RemoveAll` then `worktree prune --verbose`), can that mean configureWorktree()'s `os.WriteFile(worktree/.git, gitdir: ...)` and the checkout fight over the same path, leaving the worktree pointing at attacker bytes, so that the invariant “the worktree's `.git` link file is written by git-sync and never by repo content” no longer holds and the outcome is git-sync operating against an attacker-defined gitdir: config, hooks, and object store?

## Target
- File/function: [main.go](main.go) — `repoSync.removeWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits a file literally named `.git` at the worktree root. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: configureWorktree()'s `os.WriteFile(worktree/.git, gitdir: ...)` and the checkout fight over the same path, leaving the worktree pointing at attacker bytes
- Invariant to test: the worktree's `.git` link file is written by git-sync and never by repo content
- Expected Immunefi impact: git-sync operating against an attacker-defined gitdir: config, hooks, and object store (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert the worktree tree hash equals `git ls-tree -r <hash>` from the server
