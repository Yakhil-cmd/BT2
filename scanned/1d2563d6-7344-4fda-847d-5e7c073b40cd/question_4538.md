# Q4538: repoSync.createWorktree — many small files under default flags

## Question
Does createWorktree() and its `worktree add --force --detach <path> <hash> --no-checkout` stay safe when an attacker pushes a revision with millions of tiny files or extremely deep directory nesting in a default deployment (no sparse checkout, submodules recursive by default) — or can checkout and later `fsck`/RemoveAll blow past --sync-timeout, leaving half-materialised worktrees behind each period, violating “per-sync work is bounded and timeouts leave no residue” and producing volume exhaustion and permanent unavailability of fresh data?

## Target
- File/function: [main.go](main.go) — `repoSync.createWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Pushes a revision with millions of tiny files or extremely deep directory nesting. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: checkout and later `fsck`/RemoveAll blow past --sync-timeout, leaving half-materialised worktrees behind each period
- Invariant to test: per-sync work is bounded and timeouts leave no residue
- Expected Immunefi impact: volume exhaustion and permanent unavailability of fresh data (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once with the fixture and assert no subprocess other than the configured `--git` binary was executed (strace/`GIT_TRACE=1`)
