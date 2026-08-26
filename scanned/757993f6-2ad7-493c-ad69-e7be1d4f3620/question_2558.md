# Q2558: repoSync.createWorktree — no checkout window under crash resume

## Question
Starting from a resume after the previous process died inside configureWorktree(), can an attacker who keeps the process busy so the window between `worktree add --no-checkout` and the `reset --hard` in configureWorktree() is long drive createWorktree() and its `worktree add --force --detach <path> <hash> --no-checkout` to a state where a consumer or a hook that reaches the worktree path in that window sees an empty or partial tree, defeating “no path outside git-sync ever observes an unfinished worktree” and causing consumers executing a partially populated tree?

## Target
- File/function: [main.go](main.go) — `repoSync.createWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Keeps the process busy so the window between `worktree add --no-checkout` and the `reset --hard` in configureWorktree() is long. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a consumer or a hook that reaches the worktree path in that window sees an empty or partial tree
- Invariant to test: no path outside git-sync ever observes an unfinished worktree
- Expected Immunefi impact: consumers executing a partially populated tree (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: build the malicious commit locally, sync once, then assert nothing was created or modified outside --root (`find / -newer` on a scratch container)
