# Q4386: absPath.Join — root symlink normalise under group write

## Question
Can an unprivileged attacker who plants a symlink component inside --root that appears after the initial `EvalSymlinks` normalisation, under `--group-write` enabled, so the umask is 0002, reach a state where — in absPath.Join()/Split()/Canonical(), which clean paths without verifying containment in --root — later Join()/Split() operations resolve through it, moving worktree and link operations outside the normalised root, breaking the invariant that root normalisation holds for the process lifetime and yielding writes and deletes outside --root?

## Target
- File/function: [abspath.go](abspath.go) — `absPath.Join / Split / Canonical`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Plants a symlink component inside --root that appears after the initial `EvalSymlinks` normalisation. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: later Join()/Split() operations resolve through it, moving worktree and link operations outside the normalised root
- Invariant to test: root normalisation holds for the process lifetime
- Expected Immunefi impact: writes and deletes outside --root (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert every path git-sync creates under the link directory is owned by git-sync and not writable by other UIDs
