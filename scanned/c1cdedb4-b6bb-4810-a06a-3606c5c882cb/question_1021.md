# Q1021: repoSync.initRepo — gitmodules dotgit path under shallow submodules

## Question
Under `--submodules=shallow` with `--depth` set, an attacker commits a submodule whose path collides with `.git` handling or with an existing worktree administrative directory. In the origin remote that relative-path submodules resolve against, set in initRepo(), can that mean submodule init writes into repository metadata that later git invocations trust, so that the invariant “submodule materialisation never touches repository metadata” no longer holds and the outcome is code execution via attacker-authored git config/hooks?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits a submodule whose path collides with `.git` handling or with an existing worktree administrative directory. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: submodule init writes into repository metadata that later git invocations trust
- Invariant to test: submodule materialisation never touches repository metadata
- Expected Immunefi impact: code execution via attacker-authored git config/hooks (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
