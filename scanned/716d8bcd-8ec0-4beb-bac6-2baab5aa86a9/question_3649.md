# Q3649: repoSync.initRepo — submodule symlink escape under submodules off

## Question
Does the origin remote that relative-path submodules resolve against, set in initRepo() stay safe when an attacker combines a symlink in the superproject with a submodule path that traverses it in `--submodules=off`, where the operator believes no submodule content is fetched — or can submodule content is written outside the worktree through the symlink, violating “submodule writes resolve inside the worktree after symlink resolution” and producing arbitrary file write outside --root?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Combines a symlink in the superproject with a submodule path that traverses it. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: submodule content is written outside the worktree through the symlink
- Invariant to test: submodule writes resolve inside the worktree after symlink resolution
- Expected Immunefi impact: arbitrary file write outside --root (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
