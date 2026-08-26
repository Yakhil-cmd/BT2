# Q2082: absPath.Join — publish before materialise under shared volume

## Question
Can an unprivileged attacker who makes submodule or LFS materialisation lag the superproject checkout, under a shared volume readable and traversable by a co-tenant container, reach a state where — in absPath.Join()/Split()/Canonical(), which clean paths without verifying containment in --root — the link is swapped to a worktree whose content is still being written, breaking the invariant that publish happens strictly after the worktree is complete and yielding consumers executing a partially populated tree?

## Target
- File/function: [abspath.go](abspath.go) — `absPath.Join / Split / Canonical`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Makes submodule or LFS materialisation lag the superproject checkout. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the link is swapped to a worktree whose content is still being written
- Invariant to test: publish happens strictly after the worktree is complete
- Expected Immunefi impact: consumers executing a partially populated tree (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
