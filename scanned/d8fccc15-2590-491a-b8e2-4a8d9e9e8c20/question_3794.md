# Q3794: repoSync.removeStaleWorktrees — worktree admin residue under shared volume

## Question
Does removeStaleWorktrees(): the mtime-vs-staleTimeout predicate that must never delete the current worktree stay safe when an attacker makes `worktree prune` leave `.git/worktrees/<hash>` entries that reference removed paths in a shared volume that a co-tenant container can also write into — or can later `worktree add` for the same hash fails, blocking republish of that revision, violating “administrative worktree state stays consistent with disk” and producing permanent denial of updates for a given revision?

## Target
- File/function: [main.go](main.go) — `repoSync.removeStaleWorktrees`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Makes `worktree prune` leave `.git/worktrees/<hash>` entries that reference removed paths. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: later `worktree add` for the same hash fails, blocking republish of that revision
- Invariant to test: administrative worktree state stays consistent with disk
- Expected Immunefi impact: permanent denial of updates for a given revision (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run several periods against the fixture and assert --root file count and byte size stay bounded
