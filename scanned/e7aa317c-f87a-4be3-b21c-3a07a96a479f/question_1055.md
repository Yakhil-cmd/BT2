# Q1055: repoSync.configureWorktree — gitdir relpath escape under group write

## Question
Does configureWorktree(): the relative `.git` file rewrite, sparse-checkout wiring, `reset --hard <hash> --`, and submodule update stay safe when an attacker supplies content and a directory shape that makes `filepath.Rel(worktree, root)` produce a traversal the attacker anticipated in a deployment using `--group-write`, where the umask is 0002 and the volume is shared with a non-root consumer — or can the `gitdir:` pointer written into the worktree resolves to a path the attacker can influence from inside the published tree, violating “the gitdir pointer always resolves inside --root” and producing attacker-controlled git metadata for every later command run in the worktree?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Supplies content and a directory shape that makes `filepath.Rel(worktree, root)` produce a traversal the attacker anticipated. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the `gitdir:` pointer written into the worktree resolves to a path the attacker can influence from inside the published tree
- Invariant to test: the gitdir pointer always resolves inside --root
- Expected Immunefi impact: attacker-controlled git metadata for every later command run in the worktree (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: build the malicious commit locally, sync once, then assert nothing was created or modified outside --root (`find / -newer` on a scratch container)
