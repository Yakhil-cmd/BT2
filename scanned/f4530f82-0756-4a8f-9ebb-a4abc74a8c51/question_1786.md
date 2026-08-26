# Q1786: repoSync.SetupDefaultGitConfigs — submodule huge history under http auth

## Question
Starting from HTTPS auth with `--username`/`$GITSYNC_PASSWORD` cached by `credential.helper cache`, can an attacker who points a submodule at a repository with enormous history that `--depth` does not bound the same way drive the global git config git-sync installs before any submodule work (credential.helper cache, core.askPass true) to a state where the shallow superproject pulls an unbounded submodule, blowing the volume budget, defeating “depth limits apply consistently to submodules” and causing volume exhaustion / node disk pressure?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupDefaultGitConfigs`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Points a submodule at a repository with enormous history that `--depth` does not bound the same way. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the shallow superproject pulls an unbounded submodule, blowing the volume budget
- Invariant to test: depth limits apply consistently to submodules
- Expected Immunefi impact: volume exhaustion / node disk pressure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
