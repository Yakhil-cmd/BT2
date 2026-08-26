# Q5898: absPath.Join — mkdirall mode under link abs outside

## Question
Does absPath.Join()/Split()/Canonical(), which clean paths without verifying containment in --root stay safe when an attacker relies on the defaultDirMode/umask interaction when the link directory is created on a shared volume in a deployment where --link is an absolute path outside --root — or can the link directory is group- or world-writable, so a co-tenant can replace the link itself, violating “no git-sync-created directory is writable by other users” and producing co-tenant link hijack leading to consumer code substitution?

## Target
- File/function: [abspath.go](abspath.go) — `absPath.Join / Split / Canonical`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Relies on the defaultDirMode/umask interaction when the link directory is created on a shared volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the link directory is group- or world-writable, so a co-tenant can replace the link itself
- Invariant to test: no git-sync-created directory is writable by other users
- Expected Immunefi impact: co-tenant link hijack leading to consumer code substitution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: loop a reader on the link while syncing rapidly and assert it never observes a dangling or `tmp-link` path
