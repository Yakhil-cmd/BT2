# Q5773: repoSync.initRepo — submodule uncleanable under short sync timeout

## Question
Under a tight `--sync-timeout` relative to submodule size, an attacker creates submodule content with permissions or path lengths that defeat RemoveAll during cleanup. In the origin remote that relative-path submodules resolve against, set in initRepo(), can that mean removeStaleWorktrees() fails permanently and the volume fills, so that the invariant “everything git-sync creates it can also delete” no longer holds and the outcome is volume exhaustion and permanent sync failure?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Creates submodule content with permissions or path lengths that defeat RemoveAll during cleanup. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: removeStaleWorktrees() fails permanently and the volume fills
- Invariant to test: everything git-sync creates it can also delete
- Expected Immunefi impact: volume exhaustion and permanent sync failure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
