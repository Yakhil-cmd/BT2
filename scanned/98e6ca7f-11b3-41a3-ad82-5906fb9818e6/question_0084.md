# Q0084: repoSync.currentWorktree — link inside tree under subpath mount

## Question
Starting from a consumer that mounts a subPath of the shared volume rather than the whole volume, can an attacker who commits a file or directory at the repo path that --link resolves to when --link is relative to --root drive currentWorktree(): `os.Readlink(link)` and the absolute-vs-relative target interpretation to a state where the checked-out entry and the published symlink contend for one path, so the link ends up pointing at attacker-committed content instead of a worktree, defeating “the --link path is owned exclusively by git-sync and never by repo content” and causing consumers loading attacker-chosen files through the documented link contract?

## Target
- File/function: [main.go](main.go) — `repoSync.currentWorktree`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Commits a file or directory at the repo path that --link resolves to when --link is relative to --root. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the checked-out entry and the published symlink contend for one path, so the link ends up pointing at attacker-committed content instead of a worktree
- Invariant to test: the --link path is owned exclusively by git-sync and never by repo content
- Expected Immunefi impact: consumers loading attacker-chosen files through the documented link contract (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
