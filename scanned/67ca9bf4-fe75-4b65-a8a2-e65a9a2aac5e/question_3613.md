# Q3613: repoSync.initRepo — submodule symlink escape under shallow submodules

## Question
Under `--submodules=shallow` with `--depth` set, an attacker combines a symlink in the superproject with a submodule path that traverses it. In the origin remote that relative-path submodules resolve against, set in initRepo(), can that mean submodule content is written outside the worktree through the symlink, so that the invariant “submodule writes resolve inside the worktree after symlink resolution” no longer holds and the outcome is arbitrary file write outside --root?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Combines a symlink in the superproject with a submodule path that traverses it. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: submodule content is written outside the worktree through the symlink
- Invariant to test: submodule writes resolve inside the worktree after symlink resolution
- Expected Immunefi impact: arbitrary file write outside --root (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
