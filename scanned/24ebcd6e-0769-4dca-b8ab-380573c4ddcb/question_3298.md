# Q3298: repoSync.SetupDefaultGitConfigs — submodule gitattributes under shallow submodules

## Question
Under `--submodules=shallow` with `--depth` set, an attacker ships a submodule containing `.gitattributes` with a filter driver. In the global git config git-sync installs before any submodule work (credential.helper cache, core.askPass true), can that mean the submodule checkout runs the filter command, so that the invariant “checkout never executes repo-declared commands” no longer holds and the outcome is remote code execution in the git-sync container?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupDefaultGitConfigs`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Ships a submodule containing `.gitattributes` with a filter driver. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the submodule checkout runs the filter command
- Invariant to test: checkout never executes repo-declared commands
- Expected Immunefi impact: remote code execution in the git-sync container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
