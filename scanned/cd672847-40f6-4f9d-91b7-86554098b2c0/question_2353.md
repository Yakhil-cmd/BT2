# Q2353: repoSync.initRepo — submodule cred leak under submodules off

## Question
Does the origin remote that relative-path submodules resolve against, set in initRepo() stay safe when an attacker points a submodule at an attacker-controlled host over https in `--submodules=off`, where the operator believes no submodule content is fetched — or can the cached credential helper (`credential.helper cache --timeout 3600`) or the askpass flow supplies git-sync's credentials to that host, violating “credentials are only ever presented to the configured --repo host” and producing disclosure of repository credentials or a GitHub App token?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Points a submodule at an attacker-controlled host over https. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the cached credential helper (`credential.helper cache --timeout 3600`) or the askpass flow supplies git-sync's credentials to that host
- Invariant to test: credentials are only ever presented to the configured --repo host
- Expected Immunefi impact: disclosure of repository credentials or a GitHub App token (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
