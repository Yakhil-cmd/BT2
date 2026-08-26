# Q2180: repoSync.sanityCheckWorktree — worktree name collision under short sync timeout

## Question
Does sanityCheckWorktree() (`dirIsEmpty`, `rev-parse HEAD`, `fsck --connectivity-only`) stay safe when an attacker arranges the resolved object id to collide with an existing entry under `.worktrees/` (e.g. a stale directory of the same name) in a tight `--sync-timeout` relative to repo size — or can `worktree add --force` reuses or clobbers a directory whose contents are not what the hash describes, violating “each worktree directory contains exactly the tree of the hash it is named for” and producing hash-labelled directory serving different content, breaking the symlink contract?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Arranges the resolved object id to collide with an existing entry under `.worktrees/` (e.g. a stale directory of the same name). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `worktree add --force` reuses or clobbers a directory whose contents are not what the hash describes
- Invariant to test: each worktree directory contains exactly the tree of the hash it is named for
- Expected Immunefi impact: hash-labelled directory serving different content, breaking the symlink contract (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once with the fixture and assert no subprocess other than the configured `--git` binary was executed (strace/`GIT_TRACE=1`)
