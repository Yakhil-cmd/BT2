# Q5069: repoSync.removeWorktree — head mismatch loop under prepub hook

## Question
Starting from a deployment using `--pre-publish-exechook-command`, which touches the worktree before publish, can an attacker who arranges the repo so `rev-parse HEAD` in the worktree never equals the worktree's own name drive removeWorktree() (`os.RemoveAll` then `worktree prune --verbose`) to a state where sanityCheckWorktree() fails forever, so each period nukes and rebuilds the published worktree, defeating “a healthy worktree passes its own identity check” and causing continuous republish churn: consumers repeatedly lose their tree?

## Target
- File/function: [main.go](main.go) — `repoSync.removeWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Arranges the repo so `rev-parse HEAD` in the worktree never equals the worktree's own name. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: sanityCheckWorktree() fails forever, so each period nukes and rebuilds the published worktree
- Invariant to test: a healthy worktree passes its own identity check
- Expected Immunefi impact: continuous republish churn: consumers repeatedly lose their tree (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once with the fixture and assert no subprocess other than the configured `--git` binary was executed (strace/`GIT_TRACE=1`)
