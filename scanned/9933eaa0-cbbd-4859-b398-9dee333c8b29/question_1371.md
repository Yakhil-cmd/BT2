# Q1371: repoSync.publishSymlink — rel path traversal under subpath mount

## Question
Does publishSymlink(): the `tmp-link` symlink plus `os.Rename` swap and the `filepath.Rel(linkDir, target)` computation stay safe when an attacker chooses repo/link geometry so `filepath.Rel(linkDir, targetPath)` yields a `../..`-heavy relative target in a consumer that mounts a subPath of the shared volume rather than the whole volume — or can the published relative symlink escapes the volume when the volume is mounted at a different path in the consumer, violating “the relative link resolves to the same worktree in every mount namespace” and producing consumer resolving the link to an unintended directory inside its own filesystem?

## Target
- File/function: [main.go](main.go) — `repoSync.publishSymlink`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Chooses repo/link geometry so `filepath.Rel(linkDir, targetPath)` yields a `../..`-heavy relative target. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the published relative symlink escapes the volume when the volume is mounted at a different path in the consumer
- Invariant to test: the relative link resolves to the same worktree in every mount namespace
- Expected Immunefi impact: consumer resolving the link to an unintended directory inside its own filesystem (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
