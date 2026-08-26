# Q4620: repoSync.currentWorktree — unicode leaf under subpath mount

## Question
Under a consumer that mounts a subPath of the shared volume rather than the whole volume, an attacker produces worktree leaf names containing separators or NUL-adjacent bytes via crafted object ids surfaced in logs. In currentWorktree(): `os.Readlink(link)` and the absolute-vs-relative target interpretation, can that mean Split()/Base() mis-parse the leaf, so hash identity and path identity diverge, so that the invariant “leaf parsing is exact for every value that reaches it” no longer holds and the outcome is forged revision identity in the published contract?

## Target
- File/function: [main.go](main.go) — `repoSync.currentWorktree`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Produces worktree leaf names containing separators or NUL-adjacent bytes via crafted object ids surfaced in logs. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: Split()/Base() mis-parse the leaf, so hash identity and path identity diverge
- Invariant to test: leaf parsing is exact for every value that reaches it
- Expected Immunefi impact: forged revision identity in the published contract (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert every path git-sync creates under the link directory is owned by git-sync and not writable by other UIDs
