# Q4180: repoSync.configureWorktree — submodule slow remote under shared volume

## Question
Can an unprivileged attacker who points a submodule at a host that accepts connections and then stalls, under a shared volume where the published tree is read by another container, reach a state where — in the `submodule update --init [--recursive] [--depth N]` invocation in configureWorktree() — every sync blocks until --sync-timeout, so no publish ever completes again, breaking the invariant that one uncooperative submodule host cannot stall all syncing indefinitely and yielding permanent denial of updates to the consuming workload?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Points a submodule at a host that accepts connections and then stalls. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: every sync blocks until --sync-timeout, so no publish ever completes again
- Invariant to test: one uncooperative submodule host cannot stall all syncing indefinitely
- Expected Immunefi impact: permanent denial of updates to the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
