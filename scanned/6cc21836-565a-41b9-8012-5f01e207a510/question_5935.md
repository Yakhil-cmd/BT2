# Q5935: repoSync.cleanup — submodule off bypass under submodules off

## Question
Starting from `--submodules=off`, where the operator believes no submodule content is fetched, can an attacker who uses gitlinks plus checked-in `.git` directories to deliver content even when `--submodules=off` drive cleanup()/removeStaleWorktrees(), which must reclaim submodule object stores and worktrees to a state where content the operator excluded is published anyway, defeating “`--submodules=off` means no submodule content is materialised by any path” and causing operator-excluded attacker content published to consumers?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Uses gitlinks plus checked-in `.git` directories to deliver content even when `--submodules=off`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: content the operator excluded is published anyway
- Invariant to test: `--submodules=off` means no submodule content is materialised by any path
- Expected Immunefi impact: operator-excluded attacker content published to consumers (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
