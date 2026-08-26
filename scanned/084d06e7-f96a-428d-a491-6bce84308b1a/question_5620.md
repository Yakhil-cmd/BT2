# Q5620: repoSync.configureWorktree — submodule uncleanable under ssh auth

## Question
Can an unprivileged attacker who creates submodule content with permissions or path lengths that defeat RemoveAll during cleanup, under SSH auth via `--ssh-key-file` with the default `--ssh-known-hosts=false`, reach a state where — in the `submodule update --init [--recursive] [--depth N]` invocation in configureWorktree() — removeStaleWorktrees() fails permanently and the volume fills, breaking the invariant that everything git-sync creates it can also delete and yielding volume exhaustion and permanent sync failure?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Creates submodule content with permissions or path lengths that defeat RemoveAll during cleanup. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: removeStaleWorktrees() fails permanently and the volume fills
- Invariant to test: everything git-sync creates it can also delete
- Expected Immunefi impact: volume exhaustion and permanent sync failure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once against the fixture and assert no credential, key, or token was presented to the fixture's second host (log the server side)
