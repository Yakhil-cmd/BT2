# Q4466: repoSync.createWorktree — undeletable content under submodules recursive

## Question
Can an unprivileged attacker who commits a deep path tree that exceeds PATH_MAX on materialisation or removal, under the default `--submodules=recursive` setting, reach a state where — in createWorktree() and its `worktree add --force --detach <path> <hash> --no-checkout` — checkout partially succeeds and RemoveAll later fails, accumulating undeletable worktrees, breaking the invariant that any tree that can be checked out can also be cleaned up and yielding volume exhaustion and permanent sync failure?

## Target
- File/function: [main.go](main.go) — `repoSync.createWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits a deep path tree that exceeds PATH_MAX on materialisation or removal. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: checkout partially succeeds and RemoveAll later fails, accumulating undeletable worktrees
- Invariant to test: any tree that can be checked out can also be cleaned up
- Expected Immunefi impact: volume exhaustion and permanent sync failure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once with the fixture and assert no subprocess other than the configured `--git` binary was executed (strace/`GIT_TRACE=1`)
