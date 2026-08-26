# Q3937: repoSync.initRepo — submodule slow remote under shallow submodules

## Question
Does the origin remote that relative-path submodules resolve against, set in initRepo() stay safe when an attacker points a submodule at a host that accepts connections and then stalls in `--submodules=shallow` with `--depth` set — or can every sync blocks until --sync-timeout, so no publish ever completes again, violating “one uncooperative submodule host cannot stall all syncing indefinitely” and producing permanent denial of updates to the consuming workload?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Points a submodule at a host that accepts connections and then stalls. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: every sync blocks until --sync-timeout, so no publish ever completes again
- Invariant to test: one uncooperative submodule host cannot stall all syncing indefinitely
- Expected Immunefi impact: permanent denial of updates to the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
