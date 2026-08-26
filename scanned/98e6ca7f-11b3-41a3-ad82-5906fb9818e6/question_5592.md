# Q5592: repoSync.currentWorktree — double publish hash under subpath mount

## Question
Can an unprivileged attacker who gets two different trees published under the same hash across a wipe-and-resync, under a consumer that mounts a subPath of the shared volume rather than the whole volume, reach a state where — in currentWorktree(): `os.Readlink(link)` and the absolute-vs-relative target interpretation — the contract's hash-leaf identity no longer uniquely identifies content on the volume, breaking the invariant that hash leaf uniquely determines published bytes and yielding undetected content substitution behind a stable hash?

## Target
- File/function: [main.go](main.go) — `repoSync.currentWorktree`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Gets two different trees published under the same hash across a wipe-and-resync. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the contract's hash-leaf identity no longer uniquely identifies content on the volume
- Invariant to test: hash leaf uniquely determines published bytes
- Expected Immunefi impact: undetected content substitution behind a stable hash (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert every path git-sync creates under the link directory is owned by git-sync and not writable by other UIDs
