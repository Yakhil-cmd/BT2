# Q2389: repoSync.initRepo — submodule cred leak under ssh auth

## Question
Starting from SSH auth via `--ssh-key-file` with the default `--ssh-known-hosts=false`, can an attacker who points a submodule at an attacker-controlled host over https drive the origin remote that relative-path submodules resolve against, set in initRepo() to a state where the cached credential helper (`credential.helper cache --timeout 3600`) or the askpass flow supplies git-sync's credentials to that host, defeating “credentials are only ever presented to the configured --repo host” and causing disclosure of repository credentials or a GitHub App token?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Points a submodule at an attacker-controlled host over https. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the cached credential helper (`credential.helper cache --timeout 3600`) or the askpass flow supplies git-sync's credentials to that host
- Invariant to test: credentials are only ever presented to the configured --repo host
- Expected Immunefi impact: disclosure of repository credentials or a GitHub App token (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
