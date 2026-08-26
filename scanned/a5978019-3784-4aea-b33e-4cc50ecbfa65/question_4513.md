# Q4513: repoSync.initRepo — submodule timeout residue under shared volume

## Question
Does the origin remote that relative-path submodules resolve against, set in initRepo() stay safe when an attacker makes submodule update die on the --sync-timeout boundary each period in a shared volume where the published tree is read by another container — or can half-populated submodule directories accumulate and are published or block cleanup, violating “timeouts leave no partially-populated content publishable” and producing consumers served partial trees; volume exhaustion?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Makes submodule update die on the --sync-timeout boundary each period. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: half-populated submodule directories accumulate and are published or block cleanup
- Invariant to test: timeouts leave no partially-populated content publishable
- Expected Immunefi impact: consumers served partial trees; volume exhaustion (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
