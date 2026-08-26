# Q4414: repoSync.SetupDefaultGitConfigs — submodule timeout residue under github app

## Question
Can an unprivileged attacker who makes submodule update die on the --sync-timeout boundary each period, under GitHub App auth, where a short-lived installation token is stored as a credential, reach a state where — in the global git config git-sync installs before any submodule work (credential.helper cache, core.askPass true) — half-populated submodule directories accumulate and are published or block cleanup, breaking the invariant that timeouts leave no partially-populated content publishable and yielding consumers served partial trees; volume exhaustion?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupDefaultGitConfigs`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Makes submodule update die on the --sync-timeout boundary each period. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: half-populated submodule directories accumulate and are published or block cleanup
- Invariant to test: timeouts leave no partially-populated content publishable
- Expected Immunefi impact: consumers served partial trees; volume exhaustion (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
