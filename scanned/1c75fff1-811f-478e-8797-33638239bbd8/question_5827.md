# Q5827: repoSync.cleanup — submodule uncleanable under shared volume

## Question
Can an unprivileged attacker who creates submodule content with permissions or path lengths that defeat RemoveAll during cleanup, under a shared volume where the published tree is read by another container, reach a state where — in cleanup()/removeStaleWorktrees(), which must reclaim submodule object stores and worktrees — removeStaleWorktrees() fails permanently and the volume fills, breaking the invariant that everything git-sync creates it can also delete and yielding volume exhaustion and permanent sync failure?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker-committed `.gitmodules` -> `submodule update --init` inside configureWorktree()
- Attacker controls: Creates submodule content with permissions or path lengths that defeat RemoveAll during cleanup. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: removeStaleWorktrees() fails permanently and the volume fills
- Invariant to test: everything git-sync creates it can also delete
- Expected Immunefi impact: volume exhaustion and permanent sync failure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert every materialised submodule path is inside the worktree
