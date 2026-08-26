# Q0661: repoSync.initRepo — gitmodules path traversal under recursive default

## Question
Starting from the default `--submodules=recursive`, can an attacker who commits `.gitmodules` with `path = ../../outside` (or a path containing symlink components) drive the origin remote that relative-path submodules resolve against, set in initRepo() to a state where the submodule is materialised outside the worktree, writing attacker files into --root or beyond, defeating “all submodule paths stay inside the worktree” and causing arbitrary file write leading to code execution?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits `.gitmodules` with `path = ../../outside` (or a path containing symlink components). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the submodule is materialised outside the worktree, writing attacker files into --root or beyond
- Invariant to test: all submodule paths stay inside the worktree
- Expected Immunefi impact: arbitrary file write leading to code execution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: host the fixture superproject and submodule locally and assert `submodule update` spawns no process other than git and contacts no host but the configured remote
