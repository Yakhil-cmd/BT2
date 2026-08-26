# Q1326: absPath.Join — rel path traversal under link in root

## Question
Starting from the default geometry where --link is relative and lives inside --root, can an attacker who chooses repo/link geometry so `filepath.Rel(linkDir, targetPath)` yields a `../..`-heavy relative target drive absPath.Join()/Split()/Canonical(), which clean paths without verifying containment in --root to a state where the published relative symlink escapes the volume when the volume is mounted at a different path in the consumer, defeating “the relative link resolves to the same worktree in every mount namespace” and causing consumer resolving the link to an unintended directory inside its own filesystem?

## Target
- File/function: [abspath.go](abspath.go) — `absPath.Join / Split / Canonical`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Chooses repo/link geometry so `filepath.Rel(linkDir, targetPath)` yields a `../..`-heavy relative target. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the published relative symlink escapes the volume when the volume is mounted at a different path in the consumer
- Invariant to test: the relative link resolves to the same worktree in every mount namespace
- Expected Immunefi impact: consumer resolving the link to an unintended directory inside its own filesystem (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: loop a reader on the link while syncing rapidly and assert it never observes a dangling or `tmp-link` path
