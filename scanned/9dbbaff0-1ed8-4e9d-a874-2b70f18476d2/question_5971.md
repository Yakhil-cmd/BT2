# Q5971: repoSync.cleanup — submodule off bypass under ssh auth

## Question
Can an unprivileged attacker who uses gitlinks plus checked-in `.git` directories to deliver content even when `--submodules=off`, under SSH auth via `--ssh-key-file` with the default `--ssh-known-hosts=false`, reach a state where — in cleanup()/removeStaleWorktrees(), which must reclaim submodule object stores and worktrees — content the operator excluded is published anyway, breaking the invariant that `--submodules=off` means no submodule content is materialised by any path and yielding operator-excluded attacker content published to consumers?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Uses gitlinks plus checked-in `.git` directories to deliver content even when `--submodules=off`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: content the operator excluded is published anyway
- Invariant to test: `--submodules=off` means no submodule content is materialised by any path
- Expected Immunefi impact: operator-excluded attacker content published to consumers (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: host the fixture superproject and submodule locally and assert `submodule update` spawns no process other than git and contacts no host but the configured remote
