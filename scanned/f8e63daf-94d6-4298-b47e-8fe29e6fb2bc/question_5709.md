# Q5709: repoSync.worktreeFor — double publish hash under short period

## Question
Can an unprivileged attacker who gets two different trees published under the same hash across a wipe-and-resync, under a sub-second-to-seconds `--period`, so publishes are frequent, reach a state where — in worktreeFor()/worktree.Hash(), which derive identity from the leaf name of `.worktrees/<hash>` — the contract's hash-leaf identity no longer uniquely identifies content on the volume, breaking the invariant that hash leaf uniquely determines published bytes and yielding undetected content substitution behind a stable hash?

## Target
- File/function: [main.go](main.go) — `repoSync.worktreeFor / worktree.Hash`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Gets two different trees published under the same hash across a wipe-and-resync. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the contract's hash-leaf identity no longer uniquely identifies content on the volume
- Invariant to test: hash leaf uniquely determines published bytes
- Expected Immunefi impact: undetected content substitution behind a stable hash (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
