# Q4009: repoSync.initRepo — submodule slow remote under ssh auth

## Question
Can an unprivileged attacker who points a submodule at a host that accepts connections and then stalls, under SSH auth via `--ssh-key-file` with the default `--ssh-known-hosts=false`, reach a state where — in the origin remote that relative-path submodules resolve against, set in initRepo() — every sync blocks until --sync-timeout, so no publish ever completes again, breaking the invariant that one uncooperative submodule host cannot stall all syncing indefinitely and yielding permanent denial of updates to the consuming workload?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Points a submodule at a host that accepts connections and then stalls. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: every sync blocks until --sync-timeout, so no publish ever completes again
- Invariant to test: one uncooperative submodule host cannot stall all syncing indefinitely
- Expected Immunefi impact: permanent denial of updates to the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
