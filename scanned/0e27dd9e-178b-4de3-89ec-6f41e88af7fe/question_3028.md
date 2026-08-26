# Q3028: repoSync.configureWorktree — submodule hook payload under ssh auth

## Question
Can an unprivileged attacker who ships a submodule whose repository contains hooks that fire on clone/checkout, under SSH auth via `--ssh-key-file` with the default `--ssh-known-hosts=false`, reach a state where — in the `submodule update --init [--recursive] [--depth N]` invocation in configureWorktree() — submodule init executes those hooks inside the container, breaking the invariant that no repo-supplied script runs during a sync and yielding remote code execution in the git-sync container?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Ships a submodule whose repository contains hooks that fire on clone/checkout. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: submodule init executes those hooks inside the container
- Invariant to test: no repo-supplied script runs during a sync
- Expected Immunefi impact: remote code execution in the git-sync container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: host the fixture superproject and submodule locally and assert `submodule update` spawns no process other than git and contacts no host but the configured remote
