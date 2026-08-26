# Q4691: repoSync.configureWorktree — many small files under stale timeout

## Question
Starting from a deployment with `--stale-worktree-timeout` set, so old worktrees linger by design, can an attacker who pushes a revision with millions of tiny files or extremely deep directory nesting drive configureWorktree(): the relative `.git` file rewrite, sparse-checkout wiring, `reset --hard <hash> --`, and submodule update to a state where checkout and later `fsck`/RemoveAll blow past --sync-timeout, leaving half-materialised worktrees behind each period, defeating “per-sync work is bounded and timeouts leave no residue” and causing volume exhaustion and permanent unavailability of fresh data?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Pushes a revision with millions of tiny files or extremely deep directory nesting. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: checkout and later `fsck`/RemoveAll blow past --sync-timeout, leaving half-materialised worktrees behind each period
- Invariant to test: per-sync work is bounded and timeouts leave no residue
- Expected Immunefi impact: volume exhaustion and permanent unavailability of fresh data (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert the worktree tree hash equals `git ls-tree -r <hash>` from the server
