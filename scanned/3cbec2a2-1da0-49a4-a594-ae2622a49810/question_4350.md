# Q4350: absPath.Join — root symlink normalise under shared volume

## Question
Starting from a shared volume readable and traversable by a co-tenant container, can an attacker who plants a symlink component inside --root that appears after the initial `EvalSymlinks` normalisation drive absPath.Join()/Split()/Canonical(), which clean paths without verifying containment in --root to a state where later Join()/Split() operations resolve through it, moving worktree and link operations outside the normalised root, defeating “root normalisation holds for the process lifetime” and causing writes and deletes outside --root?

## Target
- File/function: [abspath.go](abspath.go) — `absPath.Join / Split / Canonical`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Plants a symlink component inside --root that appears after the initial `EvalSymlinks` normalisation. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: later Join()/Split() operations resolve through it, moving worktree and link operations outside the normalised root
- Invariant to test: root normalisation holds for the process lifetime
- Expected Immunefi impact: writes and deletes outside --root (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: loop a reader on the link while syncing rapidly and assert it never observes a dangling or `tmp-link` path
