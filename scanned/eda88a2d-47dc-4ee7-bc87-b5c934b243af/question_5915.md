# Q5915: repoSync.configureWorktree — hooks in checkout under group write

## Question
Under a deployment using `--group-write`, where the umask is 0002 and the volume is shared with a non-root consumer, an attacker commits files under a path the operator's extra git config makes `core.hooksPath` (or ships hooks in a submodule's `.git`). In configureWorktree(): the relative `.git` file rewrite, sparse-checkout wiring, `reset --hard <hash> --`, and submodule update, can that mean post-checkout / post-merge hooks execute during the worktree checkout, so that the invariant “no repo-supplied script ever runs as part of a sync” no longer holds and the outcome is remote code execution in the git-sync container?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits files under a path the operator's extra git config makes `core.hooksPath` (or ships hooks in a submodule's `.git`). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: post-checkout / post-merge hooks execute during the worktree checkout
- Invariant to test: no repo-supplied script ever runs as part of a sync
- Expected Immunefi impact: remote code execution in the git-sync container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: build the malicious commit locally, sync once, then assert nothing was created or modified outside --root (`find / -newer` on a scratch container)
