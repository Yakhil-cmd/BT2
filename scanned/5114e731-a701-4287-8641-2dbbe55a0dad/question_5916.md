# Q5916: repoSync.currentWorktree — mkdirall mode under subpath mount

## Question
Under a consumer that mounts a subPath of the shared volume rather than the whole volume, an attacker relies on the defaultDirMode/umask interaction when the link directory is created on a shared volume. In currentWorktree(): `os.Readlink(link)` and the absolute-vs-relative target interpretation, can that mean the link directory is group- or world-writable, so a co-tenant can replace the link itself, so that the invariant “no git-sync-created directory is writable by other users” no longer holds and the outcome is co-tenant link hijack leading to consumer code substitution?

## Target
- File/function: [main.go](main.go) — `repoSync.currentWorktree`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Relies on the defaultDirMode/umask interaction when the link directory is created on a shared volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the link directory is group- or world-writable, so a co-tenant can replace the link itself
- Invariant to test: no git-sync-created directory is writable by other users
- Expected Immunefi impact: co-tenant link hijack leading to consumer code substitution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
