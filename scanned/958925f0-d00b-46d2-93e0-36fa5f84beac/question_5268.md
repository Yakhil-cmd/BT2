# Q5268: repoSync.currentWorktree — link outside root under subpath mount

## Question
Starting from a consumer that mounts a subPath of the shared volume rather than the whole volume, can an attacker who targets a deployment where --link is an absolute path outside --root, and controls content at that path via the shared volume drive currentWorktree(): `os.Readlink(link)` and the absolute-vs-relative target interpretation to a state where the publish writes a symlink into a directory git-sync does not own, next to attacker-reachable files, defeating “publish targets are confined to paths git-sync controls” and causing link hijack: consumer follows an attacker-supplied path?

## Target
- File/function: [main.go](main.go) — `repoSync.currentWorktree`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Targets a deployment where --link is an absolute path outside --root, and controls content at that path via the shared volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the publish writes a symlink into a directory git-sync does not own, next to attacker-reachable files
- Invariant to test: publish targets are confined to paths git-sync controls
- Expected Immunefi impact: link hijack: consumer follows an attacker-supplied path (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: loop a reader on the link while syncing rapidly and assert it never observes a dangling or `tmp-link` path
