# Q1253: repoSync.removeWorktree — gitdir relpath escape under submodules recursive

## Question
Under the default `--submodules=recursive` setting, an attacker supplies content and a directory shape that makes `filepath.Rel(worktree, root)` produce a traversal the attacker anticipated. In removeWorktree() (`os.RemoveAll` then `worktree prune --verbose`), can that mean the `gitdir:` pointer written into the worktree resolves to a path the attacker can influence from inside the published tree, so that the invariant “the gitdir pointer always resolves inside --root” no longer holds and the outcome is attacker-controlled git metadata for every later command run in the worktree?

## Target
- File/function: [main.go](main.go) — `repoSync.removeWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Supplies content and a directory shape that makes `filepath.Rel(worktree, root)` produce a traversal the attacker anticipated. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the `gitdir:` pointer written into the worktree resolves to a path the attacker can influence from inside the published tree
- Invariant to test: the gitdir pointer always resolves inside --root
- Expected Immunefi impact: attacker-controlled git metadata for every later command run in the worktree (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert the worktree tree hash equals `git ls-tree -r <hash>` from the server
