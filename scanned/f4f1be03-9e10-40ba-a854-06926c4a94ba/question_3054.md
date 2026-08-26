# Q3054: absPath.Join — touch file collision under shared volume

## Question
Starting from a shared volume readable and traversable by a co-tenant container, can an attacker who commits a file at the path --touch-file resolves to inside the published tree drive absPath.Join()/Split()/Canonical(), which clean paths without verifying containment in --root to a state where touch() rewrites or creates content inside the published worktree after publish, defeating “git-sync never mutates the contents of a published worktree” and causing published tree mutated post-publish, breaking content/hash correspondence?

## Target
- File/function: [abspath.go](abspath.go) — `absPath.Join / Split / Canonical`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Commits a file at the path --touch-file resolves to inside the published tree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: touch() rewrites or creates content inside the published worktree after publish
- Invariant to test: git-sync never mutates the contents of a published worktree
- Expected Immunefi impact: published tree mutated post-publish, breaking content/hash correspondence (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
