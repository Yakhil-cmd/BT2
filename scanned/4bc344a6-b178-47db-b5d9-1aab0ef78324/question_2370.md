# Q2370: absPath.Join — link dir mkdirall under subpath mount

## Question
Can an unprivileged attacker who commits a symlink at the parent path of --link so `os.MkdirAll(linkDir)` follows it, under a consumer that mounts a subPath of the shared volume rather than the whole volume, reach a state where — in absPath.Join()/Split()/Canonical(), which clean paths without verifying containment in --root — the link directory is created outside --root and the publish writes there, breaking the invariant that link-directory creation never follows repo-controlled symlinks and yielding arbitrary directory/symlink creation outside --root?

## Target
- File/function: [abspath.go](abspath.go) — `absPath.Join / Split / Canonical`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Commits a symlink at the parent path of --link so `os.MkdirAll(linkDir)` follows it. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the link directory is created outside --root and the publish writes there
- Invariant to test: link-directory creation never follows repo-controlled symlinks
- Expected Immunefi impact: arbitrary directory/symlink creation outside --root (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
