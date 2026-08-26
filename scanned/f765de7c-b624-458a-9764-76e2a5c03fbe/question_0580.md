# Q0580: repoSync.configureWorktree — gitmodules file url under short sync timeout

## Question
Can an unprivileged attacker who commits `.gitmodules` with `url = file:///` pointing at a path inside the container or the shared volume, under a tight `--sync-timeout` relative to submodule size, reach a state where — in the `submodule update --init [--recursive] [--depth N]` invocation in configureWorktree() — the submodule clone copies local files, including mounted secrets, into the published tree, breaking the invariant that submodule sources are remote repositories the operator configured, not local filesystem paths and yielding disclosure of mounted secrets to the consuming workload?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits `.gitmodules` with `url = file:///` pointing at a path inside the container or the shared volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the submodule clone copies local files, including mounted secrets, into the published tree
- Invariant to test: submodule sources are remote repositories the operator configured, not local filesystem paths
- Expected Immunefi impact: disclosure of mounted secrets to the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
