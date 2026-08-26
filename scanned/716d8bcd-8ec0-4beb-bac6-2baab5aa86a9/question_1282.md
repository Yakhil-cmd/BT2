# Q1282: repoSync.SetupDefaultGitConfigs — gitmodules dotgit path under shared volume

## Question
Under a shared volume where the published tree is read by another container, an attacker commits a submodule whose path collides with `.git` handling or with an existing worktree administrative directory. In the global git config git-sync installs before any submodule work (credential.helper cache, core.askPass true), can that mean submodule init writes into repository metadata that later git invocations trust, so that the invariant “submodule materialisation never touches repository metadata” no longer holds and the outcome is code execution via attacker-authored git config/hooks?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupDefaultGitConfigs`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits a submodule whose path collides with `.git` handling or with an existing worktree administrative directory. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: submodule init writes into repository metadata that later git invocations trust
- Invariant to test: submodule materialisation never touches repository metadata
- Expected Immunefi impact: code execution via attacker-authored git config/hooks (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
