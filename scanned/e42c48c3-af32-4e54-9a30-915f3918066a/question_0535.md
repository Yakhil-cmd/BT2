# Q0535: repoSync.cleanup — gitmodules file url under github app

## Question
Under GitHub App auth, where a short-lived installation token is stored as a credential, an attacker commits `.gitmodules` with `url = file:///` pointing at a path inside the container or the shared volume. In cleanup()/removeStaleWorktrees(), which must reclaim submodule object stores and worktrees, can that mean the submodule clone copies local files, including mounted secrets, into the published tree, so that the invariant “submodule sources are remote repositories the operator configured, not local filesystem paths” no longer holds and the outcome is disclosure of mounted secrets to the consuming workload?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Commits `.gitmodules` with `url = file:///` pointing at a path inside the container or the shared volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the submodule clone copies local files, including mounted secrets, into the published tree
- Invariant to test: submodule sources are remote repositories the operator configured, not local filesystem paths
- Expected Immunefi impact: disclosure of mounted secrets to the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: host the fixture superproject and submodule locally and assert `submodule update` spawns no process other than git and contacts no host but the configured remote
