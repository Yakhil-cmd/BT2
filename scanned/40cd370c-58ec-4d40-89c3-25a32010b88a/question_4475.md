# Q4475: repoSync.configureWorktree — undeletable content under submodules recursive

## Question
Under the default `--submodules=recursive` setting, an attacker commits a deep path tree that exceeds PATH_MAX on materialisation or removal. In configureWorktree(): the relative `.git` file rewrite, sparse-checkout wiring, `reset --hard <hash> --`, and submodule update, can that mean checkout partially succeeds and RemoveAll later fails, accumulating undeletable worktrees, so that the invariant “any tree that can be checked out can also be cleaned up” no longer holds and the outcome is volume exhaustion and permanent sync failure?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits a deep path tree that exceeds PATH_MAX on materialisation or removal. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: checkout partially succeeds and RemoveAll later fails, accumulating undeletable worktrees
- Invariant to test: any tree that can be checked out can also be cleaned up
- Expected Immunefi impact: volume exhaustion and permanent sync failure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: build the malicious commit locally, sync once, then assert nothing was created or modified outside --root (`find / -newer` on a scratch container)
