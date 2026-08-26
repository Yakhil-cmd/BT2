# Q4700: repoSync.sanityCheckWorktree — many small files under stale timeout

## Question
Can an unprivileged attacker who pushes a revision with millions of tiny files or extremely deep directory nesting, under a deployment with `--stale-worktree-timeout` set, so old worktrees linger by design, reach a state where — in sanityCheckWorktree() (`dirIsEmpty`, `rev-parse HEAD`, `fsck --connectivity-only`) — checkout and later `fsck`/RemoveAll blow past --sync-timeout, leaving half-materialised worktrees behind each period, breaking the invariant that per-sync work is bounded and timeouts leave no residue and yielding volume exhaustion and permanent unavailability of fresh data?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Pushes a revision with millions of tiny files or extremely deep directory nesting. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: checkout and later `fsck`/RemoveAll blow past --sync-timeout, leaving half-materialised worktrees behind each period
- Invariant to test: per-sync work is bounded and timeouts leave no residue
- Expected Immunefi impact: volume exhaustion and permanent unavailability of fresh data (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once with the fixture and assert no subprocess other than the configured `--git` binary was executed (strace/`GIT_TRACE=1`)
