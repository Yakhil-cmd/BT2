# Q4450: repoSync.SetupDefaultGitConfigs — submodule timeout residue under askpass

## Question
Under `--askpass-url` auth, where credentials are re-fetched every sync, an attacker makes submodule update die on the --sync-timeout boundary each period. In the global git config git-sync installs before any submodule work (credential.helper cache, core.askPass true), can that mean half-populated submodule directories accumulate and are published or block cleanup, so that the invariant “timeouts leave no partially-populated content publishable” no longer holds and the outcome is consumers served partial trees; volume exhaustion?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupDefaultGitConfigs`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Makes submodule update die on the --sync-timeout boundary each period. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: half-populated submodule directories accumulate and are published or block cleanup
- Invariant to test: timeouts leave no partially-populated content publishable
- Expected Immunefi impact: consumers served partial trees; volume exhaustion (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: host the fixture superproject and submodule locally and assert `submodule update` spawns no process other than git and contacts no host but the configured remote
