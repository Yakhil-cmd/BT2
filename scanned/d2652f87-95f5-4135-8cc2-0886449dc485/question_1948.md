# Q1948: repoSync.configureWorktree — submodule relative url under recursive default

## Question
Does the `submodule update --init [--recursive] [--depth N]` invocation in configureWorktree() stay safe when an attacker commits a submodule with a relative `url = ../evil` resolved against the origin remote in the default `--submodules=recursive` — or can the submodule resolves to a repository the attacker controls on the same host namespace, and credentials are sent to it, violating “relative submodule URLs resolve only to paths the operator intended” and producing credential disclosure and unauthorized content publication?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits a submodule with a relative `url = ../evil` resolved against the origin remote. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the submodule resolves to a repository the attacker controls on the same host namespace, and credentials are sent to it
- Invariant to test: relative submodule URLs resolve only to paths the operator intended
- Expected Immunefi impact: credential disclosure and unauthorized content publication (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: host the fixture superproject and submodule locally and assert `submodule update` spawns no process other than git and contacts no host but the configured remote
