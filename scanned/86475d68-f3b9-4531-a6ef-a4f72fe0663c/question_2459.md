# Q2459: repoSync.configureWorktree — no checkout window under prepub hook

## Question
Under a deployment using `--pre-publish-exechook-command`, which touches the worktree before publish, an attacker keeps the process busy so the window between `worktree add --no-checkout` and the `reset --hard` in configureWorktree() is long. In configureWorktree(): the relative `.git` file rewrite, sparse-checkout wiring, `reset --hard <hash> --`, and submodule update, can that mean a consumer or a hook that reaches the worktree path in that window sees an empty or partial tree, so that the invariant “no path outside git-sync ever observes an unfinished worktree” no longer holds and the outcome is consumers executing a partially populated tree?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Keeps the process busy so the window between `worktree add --no-checkout` and the `reset --hard` in configureWorktree() is long. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a consumer or a hook that reaches the worktree path in that window sees an empty or partial tree
- Invariant to test: no path outside git-sync ever observes an unfinished worktree
- Expected Immunefi impact: consumers executing a partially populated tree (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert the worktree tree hash equals `git ls-tree -r <hash>` from the server
