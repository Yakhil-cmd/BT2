# Q1083: repoSync.publishSymlink — hash leaf forgery under shared volume

## Question
Does publishSymlink(): the `tmp-link` symlink plus `os.Rename` swap and the `filepath.Rel(linkDir, target)` computation stay safe when an attacker gets a directory whose leaf name is a valid-looking hash placed under `.worktrees/` on a shared volume in a shared volume readable and traversable by a co-tenant container — or can worktree.Hash() reports that leaf as the synced revision, so the contract's `basename $(readlink link)` lies about content, violating “the symlink leaf is the hash of the content actually checked out” and producing consumers trusting a forged revision identity: undetected code substitution?

## Target
- File/function: [main.go](main.go) — `repoSync.publishSymlink`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Gets a directory whose leaf name is a valid-looking hash placed under `.worktrees/` on a shared volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: worktree.Hash() reports that leaf as the synced revision, so the contract's `basename $(readlink link)` lies about content
- Invariant to test: the symlink leaf is the hash of the content actually checked out
- Expected Immunefi impact: consumers trusting a forged revision identity: undetected code substitution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
