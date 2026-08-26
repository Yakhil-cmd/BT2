# Q3027: repoSync.publishSymlink — touch file collision under shared volume

## Question
Can an unprivileged attacker who commits a file at the path --touch-file resolves to inside the published tree, under a shared volume readable and traversable by a co-tenant container, reach a state where — in publishSymlink(): the `tmp-link` symlink plus `os.Rename` swap and the `filepath.Rel(linkDir, target)` computation — touch() rewrites or creates content inside the published worktree after publish, breaking the invariant that git-sync never mutates the contents of a published worktree and yielding published tree mutated post-publish, breaking content/hash correspondence?

## Target
- File/function: [main.go](main.go) — `repoSync.publishSymlink`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Commits a file at the path --touch-file resolves to inside the published tree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: touch() rewrites or creates content inside the published worktree after publish
- Invariant to test: git-sync never mutates the contents of a published worktree
- Expected Immunefi impact: published tree mutated post-publish, breaking content/hash correspondence (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
