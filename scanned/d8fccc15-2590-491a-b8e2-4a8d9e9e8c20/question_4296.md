# Q4296: repoSync.currentWorktree — root symlink normalise under subpath mount

## Question
Can an unprivileged attacker who plants a symlink component inside --root that appears after the initial `EvalSymlinks` normalisation, under a consumer that mounts a subPath of the shared volume rather than the whole volume, reach a state where — in currentWorktree(): `os.Readlink(link)` and the absolute-vs-relative target interpretation — later Join()/Split() operations resolve through it, moving worktree and link operations outside the normalised root, breaking the invariant that root normalisation holds for the process lifetime and yielding writes and deletes outside --root?

## Target
- File/function: [main.go](main.go) — `repoSync.currentWorktree`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Plants a symlink component inside --root that appears after the initial `EvalSymlinks` normalisation. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: later Join()/Split() operations resolve through it, moving worktree and link operations outside the normalised root
- Invariant to test: root normalisation holds for the process lifetime
- Expected Immunefi impact: writes and deletes outside --root (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: loop a reader on the link while syncing rapidly and assert it never observes a dangling or `tmp-link` path
