# Q2479: repoSync.cleanup — submodule cred leak under github app

## Question
Starting from GitHub App auth, where a short-lived installation token is stored as a credential, can an attacker who points a submodule at an attacker-controlled host over https drive cleanup()/removeStaleWorktrees(), which must reclaim submodule object stores and worktrees to a state where the cached credential helper (`credential.helper cache --timeout 3600`) or the askpass flow supplies git-sync's credentials to that host, defeating “credentials are only ever presented to the configured --repo host” and causing disclosure of repository credentials or a GitHub App token?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Points a submodule at an attacker-controlled host over https. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the cached credential helper (`credential.helper cache --timeout 3600`) or the askpass flow supplies git-sync's credentials to that host
- Invariant to test: credentials are only ever presented to the configured --repo host
- Expected Immunefi impact: disclosure of repository credentials or a GitHub App token (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: host the fixture superproject and submodule locally and assert `submodule update` spawns no process other than git and contacts no host but the configured remote
