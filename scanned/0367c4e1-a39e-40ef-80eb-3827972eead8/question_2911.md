# Q2911: repoSync.cleanup — submodule ssh key use under shared volume

## Question
Starting from a shared volume where the published tree is read by another container, can an attacker who points a submodule at an ssh URL on an attacker-controlled host drive cleanup()/removeStaleWorktrees(), which must reclaim submodule object stores and worktrees to a state where the `$GIT_SSH_COMMAND` built by SetupGitSSH() offers the mounted private key to that host, with StrictHostKeyChecking=no by default, defeating “the mounted SSH identity is offered only to the configured remote” and causing SSH key disclosure/abuse against an attacker-controlled server?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Points a submodule at an ssh URL on an attacker-controlled host. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the `$GIT_SSH_COMMAND` built by SetupGitSSH() offers the mounted private key to that host, with StrictHostKeyChecking=no by default
- Invariant to test: the mounted SSH identity is offered only to the configured remote
- Expected Immunefi impact: SSH key disclosure/abuse against an attacker-controlled server (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
