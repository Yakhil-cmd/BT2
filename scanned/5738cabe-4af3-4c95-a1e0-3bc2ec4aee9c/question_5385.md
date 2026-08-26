# Q5385: repoSync.worktreeFor — link outside root under short period

## Question
Starting from a sub-second-to-seconds `--period`, so publishes are frequent, can an attacker who targets a deployment where --link is an absolute path outside --root, and controls content at that path via the shared volume drive worktreeFor()/worktree.Hash(), which derive identity from the leaf name of `.worktrees/<hash>` to a state where the publish writes a symlink into a directory git-sync does not own, next to attacker-reachable files, defeating “publish targets are confined to paths git-sync controls” and causing link hijack: consumer follows an attacker-supplied path?

## Target
- File/function: [main.go](main.go) — `repoSync.worktreeFor / worktree.Hash`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Targets a deployment where --link is an absolute path outside --root, and controls content at that path via the shared volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the publish writes a symlink into a directory git-sync does not own, next to attacker-reachable files
- Invariant to test: publish targets are confined to paths git-sync controls
- Expected Immunefi impact: link hijack: consumer follows an attacker-supplied path (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert every path git-sync creates under the link directory is owned by git-sync and not writable by other UIDs
