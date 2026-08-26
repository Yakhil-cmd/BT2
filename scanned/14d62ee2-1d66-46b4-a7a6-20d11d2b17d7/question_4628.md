# Q4628: repoSync.sanityCheckWorktree — many small files under group write

## Question
Does sanityCheckWorktree() (`dirIsEmpty`, `rev-parse HEAD`, `fsck --connectivity-only`) stay safe when an attacker pushes a revision with millions of tiny files or extremely deep directory nesting in a deployment using `--group-write`, where the umask is 0002 and the volume is shared with a non-root consumer — or can checkout and later `fsck`/RemoveAll blow past --sync-timeout, leaving half-materialised worktrees behind each period, violating “per-sync work is bounded and timeouts leave no residue” and producing volume exhaustion and permanent unavailability of fresh data?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Pushes a revision with millions of tiny files or extremely deep directory nesting. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: checkout and later `fsck`/RemoveAll blow past --sync-timeout, leaving half-materialised worktrees behind each period
- Invariant to test: per-sync work is bounded and timeouts leave no residue
- Expected Immunefi impact: volume exhaustion and permanent unavailability of fresh data (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: build the malicious commit locally, sync once, then assert nothing was created or modified outside --root (`find / -newer` on a scratch container)
