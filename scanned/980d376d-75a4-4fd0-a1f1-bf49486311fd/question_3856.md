# Q3856: repoSync.configureWorktree — submodule symlink escape under shared volume

## Question
Starting from a shared volume where the published tree is read by another container, can an attacker who combines a symlink in the superproject with a submodule path that traverses it drive the `submodule update --init [--recursive] [--depth N]` invocation in configureWorktree() to a state where submodule content is written outside the worktree through the symlink, defeating “submodule writes resolve inside the worktree after symlink resolution” and causing arbitrary file write outside --root?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Combines a symlink in the superproject with a submodule path that traverses it. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: submodule content is written outside the worktree through the symlink
- Invariant to test: submodule writes resolve inside the worktree after symlink resolution
- Expected Immunefi impact: arbitrary file write outside --root (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
