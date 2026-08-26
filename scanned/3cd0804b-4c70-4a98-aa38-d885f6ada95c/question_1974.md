# Q1974: absPath.Join — publish before materialise under link in root

## Question
Under the default geometry where --link is relative and lives inside --root, an attacker makes submodule or LFS materialisation lag the superproject checkout. In absPath.Join()/Split()/Canonical(), which clean paths without verifying containment in --root, can that mean the link is swapped to a worktree whose content is still being written, so that the invariant “publish happens strictly after the worktree is complete” no longer holds and the outcome is consumers executing a partially populated tree?

## Target
- File/function: [abspath.go](abspath.go) — `absPath.Join / Split / Canonical`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Makes submodule or LFS materialisation lag the superproject checkout. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the link is swapped to a worktree whose content is still being written
- Invariant to test: publish happens strictly after the worktree is complete
- Expected Immunefi impact: consumers executing a partially populated tree (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
