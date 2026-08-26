# Q5978: repoSync.createWorktree — hooks in checkout under stale timeout

## Question
Does createWorktree() and its `worktree add --force --detach <path> <hash> --no-checkout` stay safe when an attacker commits files under a path the operator's extra git config makes `core.hooksPath` (or ships hooks in a submodule's `.git`) in a deployment with `--stale-worktree-timeout` set, so old worktrees linger by design — or can post-checkout / post-merge hooks execute during the worktree checkout, violating “no repo-supplied script ever runs as part of a sync” and producing remote code execution in the git-sync container?

## Target
- File/function: [main.go](main.go) — `repoSync.createWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits files under a path the operator's extra git config makes `core.hooksPath` (or ships hooks in a submodule's `.git`). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: post-checkout / post-merge hooks execute during the worktree checkout
- Invariant to test: no repo-supplied script ever runs as part of a sync
- Expected Immunefi impact: remote code execution in the git-sync container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert the worktree tree hash equals `git ls-tree -r <hash>` from the server
