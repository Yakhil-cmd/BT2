# Q5987: repoSync.configureWorktree — hooks in checkout under stale timeout

## Question
Starting from a deployment with `--stale-worktree-timeout` set, so old worktrees linger by design, can an attacker who commits files under a path the operator's extra git config makes `core.hooksPath` (or ships hooks in a submodule's `.git`) drive configureWorktree(): the relative `.git` file rewrite, sparse-checkout wiring, `reset --hard <hash> --`, and submodule update to a state where post-checkout / post-merge hooks execute during the worktree checkout, defeating “no repo-supplied script ever runs as part of a sync” and causing remote code execution in the git-sync container?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits files under a path the operator's extra git config makes `core.hooksPath` (or ships hooks in a submodule's `.git`). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: post-checkout / post-merge hooks execute during the worktree checkout
- Invariant to test: no repo-supplied script ever runs as part of a sync
- Expected Immunefi impact: remote code execution in the git-sync container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once with the fixture and assert no subprocess other than the configured `--git` binary was executed (strace/`GIT_TRACE=1`)
