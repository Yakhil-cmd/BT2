# Q5880: repoSync.currentWorktree — mkdirall mode under link abs outside

## Question
Can an unprivileged attacker who relies on the defaultDirMode/umask interaction when the link directory is created on a shared volume, under a deployment where --link is an absolute path outside --root, reach a state where — in currentWorktree(): `os.Readlink(link)` and the absolute-vs-relative target interpretation — the link directory is group- or world-writable, so a co-tenant can replace the link itself, breaking the invariant that no git-sync-created directory is writable by other users and yielding co-tenant link hijack leading to consumer code substitution?

## Target
- File/function: [main.go](main.go) — `repoSync.currentWorktree`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Relies on the defaultDirMode/umask interaction when the link directory is created on a shared volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the link directory is group- or world-writable, so a co-tenant can replace the link itself
- Invariant to test: no git-sync-created directory is writable by other users
- Expected Immunefi impact: co-tenant link hijack leading to consumer code substitution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert every path git-sync creates under the link directory is owned by git-sync and not writable by other UIDs
