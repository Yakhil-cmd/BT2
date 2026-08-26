# Q0913: repoSync.initRepo — gitmodules path traversal under short sync timeout

## Question
Does the origin remote that relative-path submodules resolve against, set in initRepo() stay safe when an attacker commits `.gitmodules` with `path = ../../outside` (or a path containing symlink components) in a tight `--sync-timeout` relative to submodule size — or can the submodule is materialised outside the worktree, writing attacker files into --root or beyond, violating “all submodule paths stay inside the worktree” and producing arbitrary file write leading to code execution?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits `.gitmodules` with `path = ../../outside` (or a path containing symlink components). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the submodule is materialised outside the worktree, writing attacker files into --root or beyond
- Invariant to test: all submodule paths stay inside the worktree
- Expected Immunefi impact: arbitrary file write leading to code execution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
