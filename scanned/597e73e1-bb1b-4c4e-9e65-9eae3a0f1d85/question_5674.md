# Q5674: repoSync.SetupDefaultGitConfigs — submodule uncleanable under http auth

## Question
Starting from HTTPS auth with `--username`/`$GITSYNC_PASSWORD` cached by `credential.helper cache`, can an attacker who creates submodule content with permissions or path lengths that defeat RemoveAll during cleanup drive the global git config git-sync installs before any submodule work (credential.helper cache, core.askPass true) to a state where removeStaleWorktrees() fails permanently and the volume fills, defeating “everything git-sync creates it can also delete” and causing volume exhaustion and permanent sync failure?

## Target
- File/function: [main.go](main.go) — `repoSync.SetupDefaultGitConfigs`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Creates submodule content with permissions or path lengths that defeat RemoveAll during cleanup. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: removeStaleWorktrees() fails permanently and the volume fills
- Invariant to test: everything git-sync creates it can also delete
- Expected Immunefi impact: volume exhaustion and permanent sync failure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
