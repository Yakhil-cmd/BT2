# Q1838: repoSync.createWorktree — sparse info dir race under short sync timeout

## Question
Starting from a tight `--sync-timeout` relative to repo size, can an attacker who times pushes so configureWorktree() re-copies the sparse-checkout file while a checkout of the same hash is in flight drive createWorktree() and its `worktree add --force --detach <path> <hash> --no-checkout` to a state where `.git/worktrees/<hash>/info/sparse-checkout` is half-written when `sparse-checkout init` runs, defeating “sparse configuration is fully applied before any checkout of that worktree” and causing partial/incorrect tree published as a successful sync?

## Target
- File/function: [main.go](main.go) — `repoSync.createWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Times pushes so configureWorktree() re-copies the sparse-checkout file while a checkout of the same hash is in flight. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `.git/worktrees/<hash>/info/sparse-checkout` is half-written when `sparse-checkout init` runs
- Invariant to test: sparse configuration is fully applied before any checkout of that worktree
- Expected Immunefi impact: partial/incorrect tree published as a successful sync (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once with the fixture and assert no subprocess other than the configured `--git` binary was executed (strace/`GIT_TRACE=1`)
