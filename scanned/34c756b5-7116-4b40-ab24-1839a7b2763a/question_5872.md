# Q5872: repoSync.configureWorktree — submodule off bypass under shallow submodules

## Question
Starting from `--submodules=shallow` with `--depth` set, can an attacker who uses gitlinks plus checked-in `.git` directories to deliver content even when `--submodules=off` drive the `submodule update --init [--recursive] [--depth N]` invocation in configureWorktree() to a state where content the operator excluded is published anyway, defeating “`--submodules=off` means no submodule content is materialised by any path” and causing operator-excluded attacker content published to consumers?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Uses gitlinks plus checked-in `.git` directories to deliver content even when `--submodules=off`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: content the operator excluded is published anyway
- Invariant to test: `--submodules=off` means no submodule content is materialised by any path
- Expected Immunefi impact: operator-excluded attacker content published to consumers (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
