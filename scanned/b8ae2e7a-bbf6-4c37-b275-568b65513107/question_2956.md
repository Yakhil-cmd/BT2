# Q2956: repoSync.configureWorktree — submodule hook payload under shallow submodules

## Question
Does the `submodule update --init [--recursive] [--depth N]` invocation in configureWorktree() stay safe when an attacker ships a submodule whose repository contains hooks that fire on clone/checkout in `--submodules=shallow` with `--depth` set — or can submodule init executes those hooks inside the container, violating “no repo-supplied script runs during a sync” and producing remote code execution in the git-sync container?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Ships a submodule whose repository contains hooks that fire on clone/checkout. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: submodule init executes those hooks inside the container
- Invariant to test: no repo-supplied script runs during a sync
- Expected Immunefi impact: remote code execution in the git-sync container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
