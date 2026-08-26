# Q5196: repoSync.currentWorktree — link outside root under link in root

## Question
Under the default geometry where --link is relative and lives inside --root, an attacker targets a deployment where --link is an absolute path outside --root, and controls content at that path via the shared volume. In currentWorktree(): `os.Readlink(link)` and the absolute-vs-relative target interpretation, can that mean the publish writes a symlink into a directory git-sync does not own, next to attacker-reachable files, so that the invariant “publish targets are confined to paths git-sync controls” no longer holds and the outcome is link hijack: consumer follows an attacker-supplied path?

## Target
- File/function: [main.go](main.go) — `repoSync.currentWorktree`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Targets a deployment where --link is an absolute path outside --root, and controls content at that path via the shared volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the publish writes a symlink into a directory git-sync does not own, next to attacker-reachable files
- Invariant to test: publish targets are confined to paths git-sync controls
- Expected Immunefi impact: link hijack: consumer follows an attacker-supplied path (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert every path git-sync creates under the link directory is owned by git-sync and not writable by other UIDs
