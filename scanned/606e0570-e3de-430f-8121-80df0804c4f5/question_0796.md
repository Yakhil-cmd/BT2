# Q0796: repoSync.configureWorktree — gitmodules path traversal under http auth

## Question
Does the `submodule update --init [--recursive] [--depth N]` invocation in configureWorktree() stay safe when an attacker commits `.gitmodules` with `path = ../../outside` (or a path containing symlink components) in HTTPS auth with `--username`/`$GITSYNC_PASSWORD` cached by `credential.helper cache` — or can the submodule is materialised outside the worktree, writing attacker files into --root or beyond, violating “all submodule paths stay inside the worktree” and producing arbitrary file write leading to code execution?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits `.gitmodules` with `path = ../../outside` (or a path containing symlink components). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the submodule is materialised outside the worktree, writing attacker files into --root or beyond
- Invariant to test: all submodule paths stay inside the worktree
- Expected Immunefi impact: arbitrary file write leading to code execution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: host the fixture superproject and submodule locally and assert `submodule update` spawns no process other than git and contacts no host but the configured remote
