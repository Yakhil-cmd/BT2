# Q1804: repoSync.configureWorktree — submodule huge history under github app

## Question
Does the `submodule update --init [--recursive] [--depth N]` invocation in configureWorktree() stay safe when an attacker points a submodule at a repository with enormous history that `--depth` does not bound the same way in GitHub App auth, where a short-lived installation token is stored as a credential — or can the shallow superproject pulls an unbounded submodule, blowing the volume budget, violating “depth limits apply consistently to submodules” and producing volume exhaustion / node disk pressure?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Points a submodule at a repository with enormous history that `--depth` does not bound the same way. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the shallow superproject pulls an unbounded submodule, blowing the volume budget
- Invariant to test: depth limits apply consistently to submodules
- Expected Immunefi impact: volume exhaustion / node disk pressure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
