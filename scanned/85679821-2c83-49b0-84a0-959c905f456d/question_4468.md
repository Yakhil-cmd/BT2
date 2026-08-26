# Q4468: repoSync.configureWorktree — submodule timeout residue under short sync timeout

## Question
Can an unprivileged attacker who makes submodule update die on the --sync-timeout boundary each period, under a tight `--sync-timeout` relative to submodule size, reach a state where — in the `submodule update --init [--recursive] [--depth N]` invocation in configureWorktree() — half-populated submodule directories accumulate and are published or block cleanup, breaking the invariant that timeouts leave no partially-populated content publishable and yielding consumers served partial trees; volume exhaustion?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Makes submodule update die on the --sync-timeout boundary each period. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: half-populated submodule directories accumulate and are published or block cleanup
- Invariant to test: timeouts leave no partially-populated content publishable
- Expected Immunefi impact: consumers served partial trees; volume exhaustion (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
