# Q2209: repoSync.initRepo — submodule relative url under short sync timeout

## Question
Does the origin remote that relative-path submodules resolve against, set in initRepo() stay safe when an attacker commits a submodule with a relative `url = ../evil` resolved against the origin remote in a tight `--sync-timeout` relative to submodule size — or can the submodule resolves to a repository the attacker controls on the same host namespace, and credentials are sent to it, violating “relative submodule URLs resolve only to paths the operator intended” and producing credential disclosure and unauthorized content publication?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits a submodule with a relative `url = ../evil` resolved against the origin remote. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the submodule resolves to a repository the attacker controls on the same host namespace, and credentials are sent to it
- Invariant to test: relative submodule URLs resolve only to paths the operator intended
- Expected Immunefi impact: credential disclosure and unauthorized content publication (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
