# Q1102: repoSync.SetupDefaultGitConfigs — gitmodules dotgit path under ssh auth

## Question
Can an unprivileged attacker who commits a submodule whose path collides with `.git` handling or with an existing worktree administrative directory, under SSH auth via `--ssh-key-file` with the default `--ssh-known-hosts=false`, reach a state where — in the global git config git-sync installs before any submodule work (credential.helper cache, core.askPass true) — submodule init writes into repository metadata that later git invocations trust, breaking the invariant that submodule materialisation never touches repository metadata and yielding code execution via attacker-authored git config/hooks?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupDefaultGitConfigs`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits a submodule whose path collides with `.git` handling or with an existing worktree administrative directory. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: submodule init writes into repository metadata that later git invocations trust
- Invariant to test: submodule materialisation never touches repository metadata
- Expected Immunefi impact: code execution via attacker-authored git config/hooks (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
