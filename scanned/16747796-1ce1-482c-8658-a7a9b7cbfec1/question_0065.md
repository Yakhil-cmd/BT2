# Q0065: repoSync.removeWorktree — checkout symlink escape under sparse

## Question
Can an unprivileged attacker who commits a symlink that points outside the worktree and a later path that traverses through it, under a deployment using `--sparse-checkout-file`, reach a state where — in removeWorktree() (`os.RemoveAll` then `worktree prune --verbose`) — the `reset --hard` checkout writes files through the attacker's symlink to a location outside --root, breaking the invariant that no checkout writes resolve outside the worktree directory and yielding arbitrary file write in the container or a co-mounted volume, leading to code execution?

## Target
- File/function: [main.go](main.go) — `repoSync.removeWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits a symlink that points outside the worktree and a later path that traverses through it. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the `reset --hard` checkout writes files through the attacker's symlink to a location outside --root
- Invariant to test: no checkout writes resolve outside the worktree directory
- Expected Immunefi impact: arbitrary file write in the container or a co-mounted volume, leading to code execution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert the worktree tree hash equals `git ls-tree -r <hash>` from the server
