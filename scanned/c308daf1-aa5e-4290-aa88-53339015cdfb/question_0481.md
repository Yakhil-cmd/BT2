# Q0481: repoSync.initRepo — gitmodules file url under http auth

## Question
Does the origin remote that relative-path submodules resolve against, set in initRepo() stay safe when an attacker commits `.gitmodules` with `url = file:///` pointing at a path inside the container or the shared volume in HTTPS auth with `--username`/`$GITSYNC_PASSWORD` cached by `credential.helper cache` — or can the submodule clone copies local files, including mounted secrets, into the published tree, violating “submodule sources are remote repositories the operator configured, not local filesystem paths” and producing disclosure of mounted secrets to the consuming workload?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits `.gitmodules` with `url = file:///` pointing at a path inside the container or the shared volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the submodule clone copies local files, including mounted secrets, into the published tree
- Invariant to test: submodule sources are remote repositories the operator configured, not local filesystem paths
- Expected Immunefi impact: disclosure of mounted secrets to the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: host the fixture superproject and submodule locally and assert `submodule update` spawns no process other than git and contacts no host but the configured remote
