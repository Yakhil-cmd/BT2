# Q0868: repoSync.configureWorktree — gitmodules path traversal under askpass

## Question
Can an unprivileged attacker who commits `.gitmodules` with `path = ../../outside` (or a path containing symlink components), under `--askpass-url` auth, where credentials are re-fetched every sync, reach a state where — in the `submodule update --init [--recursive] [--depth N]` invocation in configureWorktree() — the submodule is materialised outside the worktree, writing attacker files into --root or beyond, breaking the invariant that all submodule paths stay inside the worktree and yielding arbitrary file write leading to code execution?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits `.gitmodules` with `path = ../../outside` (or a path containing symlink components). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the submodule is materialised outside the worktree, writing attacker files into --root or beyond
- Invariant to test: all submodule paths stay inside the worktree
- Expected Immunefi impact: arbitrary file write leading to code execution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
