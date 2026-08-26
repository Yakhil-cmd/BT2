# Q1074: absPath.Join — hash leaf forgery under subpath mount

## Question
Can an unprivileged attacker who gets a directory whose leaf name is a valid-looking hash placed under `.worktrees/` on a shared volume, under a consumer that mounts a subPath of the shared volume rather than the whole volume, reach a state where — in absPath.Join()/Split()/Canonical(), which clean paths without verifying containment in --root — worktree.Hash() reports that leaf as the synced revision, so the contract's `basename $(readlink link)` lies about content, breaking the invariant that the symlink leaf is the hash of the content actually checked out and yielding consumers trusting a forged revision identity: undetected code substitution?

## Target
- File/function: [abspath.go](abspath.go) — `absPath.Join / Split / Canonical`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Gets a directory whose leaf name is a valid-looking hash placed under `.worktrees/` on a shared volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: worktree.Hash() reports that leaf as the synced revision, so the contract's `basename $(readlink link)` lies about content
- Invariant to test: the symlink leaf is the hash of the content actually checked out
- Expected Immunefi impact: consumers trusting a forged revision identity: undetected code substitution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert every path git-sync creates under the link directory is owned by git-sync and not writable by other UIDs
