# Q1885: repoSync.initRepo — submodule huge history under short sync timeout

## Question
Under a tight `--sync-timeout` relative to submodule size, an attacker points a submodule at a repository with enormous history that `--depth` does not bound the same way. In the origin remote that relative-path submodules resolve against, set in initRepo(), can that mean the shallow superproject pulls an unbounded submodule, blowing the volume budget, so that the invariant “depth limits apply consistently to submodules” no longer holds and the outcome is volume exhaustion / node disk pressure?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Points a submodule at a repository with enormous history that `--depth` does not bound the same way. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the shallow superproject pulls an unbounded submodule, blowing the volume budget
- Invariant to test: depth limits apply consistently to submodules
- Expected Immunefi impact: volume exhaustion / node disk pressure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
