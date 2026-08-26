# Q1892: repoSync.sanityCheckWorktree — sparse info dir race under submodules recursive

## Question
Does sanityCheckWorktree() (`dirIsEmpty`, `rev-parse HEAD`, `fsck --connectivity-only`) stay safe when an attacker times pushes so configureWorktree() re-copies the sparse-checkout file while a checkout of the same hash is in flight in the default `--submodules=recursive` setting — or can `.git/worktrees/<hash>/info/sparse-checkout` is half-written when `sparse-checkout init` runs, violating “sparse configuration is fully applied before any checkout of that worktree” and producing partial/incorrect tree published as a successful sync?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Times pushes so configureWorktree() re-copies the sparse-checkout file while a checkout of the same hash is in flight. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `.git/worktrees/<hash>/info/sparse-checkout` is half-written when `sparse-checkout init` runs
- Invariant to test: sparse configuration is fully applied before any checkout of that worktree
- Expected Immunefi impact: partial/incorrect tree published as a successful sync (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once with the fixture and assert no subprocess other than the configured `--git` binary was executed (strace/`GIT_TRACE=1`)
