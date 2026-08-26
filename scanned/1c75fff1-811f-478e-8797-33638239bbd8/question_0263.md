# Q0263: repoSync.configureWorktree — checkout symlink escape under submodules recursive

## Question
Can an unprivileged attacker who commits a symlink that points outside the worktree and a later path that traverses through it, under the default `--submodules=recursive` setting, reach a state where — in configureWorktree(): the relative `.git` file rewrite, sparse-checkout wiring, `reset --hard <hash> --`, and submodule update — the `reset --hard` checkout writes files through the attacker's symlink to a location outside --root, breaking the invariant that no checkout writes resolve outside the worktree directory and yielding arbitrary file write in the container or a co-mounted volume, leading to code execution?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits a symlink that points outside the worktree and a later path that traverses through it. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the `reset --hard` checkout writes files through the attacker's symlink to a location outside --root
- Invariant to test: no checkout writes resolve outside the worktree directory
- Expected Immunefi impact: arbitrary file write in the container or a co-mounted volume, leading to code execution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once with the fixture and assert no subprocess other than the configured `--git` binary was executed (strace/`GIT_TRACE=1`)
