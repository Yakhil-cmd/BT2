# Q1182: absPath.Join — hash leaf forgery under short period

## Question
Starting from a sub-second-to-seconds `--period`, so publishes are frequent, can an attacker who gets a directory whose leaf name is a valid-looking hash placed under `.worktrees/` on a shared volume drive absPath.Join()/Split()/Canonical(), which clean paths without verifying containment in --root to a state where worktree.Hash() reports that leaf as the synced revision, so the contract's `basename $(readlink link)` lies about content, defeating “the symlink leaf is the hash of the content actually checked out” and causing consumers trusting a forged revision identity: undetected code substitution?

## Target
- File/function: [abspath.go](abspath.go) — `absPath.Join / Split / Canonical`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Gets a directory whose leaf name is a valid-looking hash placed under `.worktrees/` on a shared volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: worktree.Hash() reports that leaf as the synced revision, so the contract's `basename $(readlink link)` lies about content
- Invariant to test: the symlink leaf is the hash of the content actually checked out
- Expected Immunefi impact: consumers trusting a forged revision identity: undetected code substitution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert every path git-sync creates under the link directory is owned by git-sync and not writable by other UIDs
