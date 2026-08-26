# Q4288: repoSync.configureWorktree — submodule timeout residue under submodules off

## Question
Starting from `--submodules=off`, where the operator believes no submodule content is fetched, can an attacker who makes submodule update die on the --sync-timeout boundary each period drive the `submodule update --init [--recursive] [--depth N]` invocation in configureWorktree() to a state where half-populated submodule directories accumulate and are published or block cleanup, defeating “timeouts leave no partially-populated content publishable” and causing consumers served partial trees; volume exhaustion?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Makes submodule update die on the --sync-timeout boundary each period. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: half-populated submodule directories accumulate and are published or block cleanup
- Invariant to test: timeouts leave no partially-populated content publishable
- Expected Immunefi impact: consumers served partial trees; volume exhaustion (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: host the fixture superproject and submodule locally and assert `submodule update` spawns no process other than git and contacts no host but the configured remote
