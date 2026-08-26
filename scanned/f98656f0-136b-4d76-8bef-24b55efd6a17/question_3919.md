# Q3919: repoSync.cleanup — submodule slow remote under recursive default

## Question
Starting from the default `--submodules=recursive`, can an attacker who points a submodule at a host that accepts connections and then stalls drive cleanup()/removeStaleWorktrees(), which must reclaim submodule object stores and worktrees to a state where every sync blocks until --sync-timeout, so no publish ever completes again, defeating “one uncooperative submodule host cannot stall all syncing indefinitely” and causing permanent denial of updates to the consuming workload?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Points a submodule at a host that accepts connections and then stalls. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: every sync blocks until --sync-timeout, so no publish ever completes again
- Invariant to test: one uncooperative submodule host cannot stall all syncing indefinitely
- Expected Immunefi impact: permanent denial of updates to the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: host the fixture superproject and submodule locally and assert `submodule update` spawns no process other than git and contacts no host but the configured remote
