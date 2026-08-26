# Q4189: repoSync.initRepo — submodule slow remote under shared volume

## Question
Under a shared volume where the published tree is read by another container, an attacker points a submodule at a host that accepts connections and then stalls. In the origin remote that relative-path submodules resolve against, set in initRepo(), can that mean every sync blocks until --sync-timeout, so no publish ever completes again, so that the invariant “one uncooperative submodule host cannot stall all syncing indefinitely” no longer holds and the outcome is permanent denial of updates to the consuming workload?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Points a submodule at a host that accepts connections and then stalls. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: every sync blocks until --sync-timeout, so no publish ever completes again
- Invariant to test: one uncooperative submodule host cannot stall all syncing indefinitely
- Expected Immunefi impact: permanent denial of updates to the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: host the fixture superproject and submodule locally and assert `submodule update` spawns no process other than git and contacts no host but the configured remote
