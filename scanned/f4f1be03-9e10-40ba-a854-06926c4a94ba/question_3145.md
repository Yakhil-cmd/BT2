# Q3145: repoSync.initRepo — submodule hook payload under askpass

## Question
Can an unprivileged attacker who ships a submodule whose repository contains hooks that fire on clone/checkout, under `--askpass-url` auth, where credentials are re-fetched every sync, reach a state where — in the origin remote that relative-path submodules resolve against, set in initRepo() — submodule init executes those hooks inside the container, breaking the invariant that no repo-supplied script runs during a sync and yielding remote code execution in the git-sync container?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Ships a submodule whose repository contains hooks that fire on clone/checkout. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: submodule init executes those hooks inside the container
- Invariant to test: no repo-supplied script runs during a sync
- Expected Immunefi impact: remote code execution in the git-sync container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
