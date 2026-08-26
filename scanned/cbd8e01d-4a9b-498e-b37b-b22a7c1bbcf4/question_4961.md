# Q4961: repoSync.removeWorktree — head mismatch loop under group write

## Question
Can an unprivileged attacker who arranges the repo so `rev-parse HEAD` in the worktree never equals the worktree's own name, under a deployment using `--group-write`, where the umask is 0002 and the volume is shared with a non-root consumer, reach a state where — in removeWorktree() (`os.RemoveAll` then `worktree prune --verbose`) — sanityCheckWorktree() fails forever, so each period nukes and rebuilds the published worktree, breaking the invariant that a healthy worktree passes its own identity check and yielding continuous republish churn: consumers repeatedly lose their tree?

## Target
- File/function: [main.go](main.go) — `repoSync.removeWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Arranges the repo so `rev-parse HEAD` in the worktree never equals the worktree's own name. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: sanityCheckWorktree() fails forever, so each period nukes and rebuilds the published worktree
- Invariant to test: a healthy worktree passes its own identity check
- Expected Immunefi impact: continuous republish churn: consumers repeatedly lose their tree (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once with the fixture and assert no subprocess other than the configured `--git` binary was executed (strace/`GIT_TRACE=1`)
