# Q5737: repoSync.initRepo — submodule uncleanable under askpass

## Question
Can an unprivileged attacker who creates submodule content with permissions or path lengths that defeat RemoveAll during cleanup, under `--askpass-url` auth, where credentials are re-fetched every sync, reach a state where — in the origin remote that relative-path submodules resolve against, set in initRepo() — removeStaleWorktrees() fails permanently and the volume fills, breaking the invariant that everything git-sync creates it can also delete and yielding volume exhaustion and permanent sync failure?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Creates submodule content with permissions or path lengths that defeat RemoveAll during cleanup. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: removeStaleWorktrees() fails permanently and the volume fills
- Invariant to test: everything git-sync creates it can also delete
- Expected Immunefi impact: volume exhaustion and permanent sync failure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: host the fixture superproject and submodule locally and assert `submodule update` spawns no process other than git and contacts no host but the configured remote
