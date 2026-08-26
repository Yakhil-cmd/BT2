# Q2245: repoSync.initRepo — submodule relative url under shared volume

## Question
Starting from a shared volume where the published tree is read by another container, can an attacker who commits a submodule with a relative `url = ../evil` resolved against the origin remote drive the origin remote that relative-path submodules resolve against, set in initRepo() to a state where the submodule resolves to a repository the attacker controls on the same host namespace, and credentials are sent to it, defeating “relative submodule URLs resolve only to paths the operator intended” and causing credential disclosure and unauthorized content publication?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits a submodule with a relative `url = ../evil` resolved against the origin remote. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the submodule resolves to a repository the attacker controls on the same host namespace, and credentials are sent to it
- Invariant to test: relative submodule URLs resolve only to paths the operator intended
- Expected Immunefi impact: credential disclosure and unauthorized content publication (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: host the fixture superproject and submodule locally and assert `submodule update` spawns no process other than git and contacts no host but the configured remote
