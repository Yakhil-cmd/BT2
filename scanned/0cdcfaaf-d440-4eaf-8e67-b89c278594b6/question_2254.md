# Q2254: repoSync.SetupDefaultGitConfigs — submodule relative url under shared volume

## Question
Can an unprivileged attacker who commits a submodule with a relative `url = ../evil` resolved against the origin remote, under a shared volume where the published tree is read by another container, reach a state where — in the global git config git-sync installs before any submodule work (credential.helper cache, core.askPass true) — the submodule resolves to a repository the attacker controls on the same host namespace, and credentials are sent to it, breaking the invariant that relative submodule URLs resolve only to paths the operator intended and yielding credential disclosure and unauthorized content publication?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupDefaultGitConfigs`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits a submodule with a relative `url = ../evil` resolved against the origin remote. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the submodule resolves to a repository the attacker controls on the same host namespace, and credentials are sent to it
- Invariant to test: relative submodule URLs resolve only to paths the operator intended
- Expected Immunefi impact: credential disclosure and unauthorized content publication (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
