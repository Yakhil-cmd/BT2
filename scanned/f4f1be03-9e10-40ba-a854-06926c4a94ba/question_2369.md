# Q2369: repoSync.removeWorktree — no checkout window under group write

## Question
Can an unprivileged attacker who keeps the process busy so the window between `worktree add --no-checkout` and the `reset --hard` in configureWorktree() is long, under a deployment using `--group-write`, where the umask is 0002 and the volume is shared with a non-root consumer, reach a state where — in removeWorktree() (`os.RemoveAll` then `worktree prune --verbose`) — a consumer or a hook that reaches the worktree path in that window sees an empty or partial tree, breaking the invariant that no path outside git-sync ever observes an unfinished worktree and yielding consumers executing a partially populated tree?

## Target
- File/function: [main.go](main.go) — `repoSync.removeWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Keeps the process busy so the window between `worktree add --no-checkout` and the `reset --hard` in configureWorktree() is long. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a consumer or a hook that reaches the worktree path in that window sees an empty or partial tree
- Invariant to test: no path outside git-sync ever observes an unfinished worktree
- Expected Immunefi impact: consumers executing a partially populated tree (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: build the malicious commit locally, sync once, then assert nothing was created or modified outside --root (`find / -newer` on a scratch container)
