# Q2595: repoSync.publishSymlink — stale link after wipe under link in root

## Question
Can an unprivileged attacker who forces the root wipe path in initRepo() while the link is live, under the default geometry where --link is relative and lives inside --root, reach a state where — in publishSymlink(): the `tmp-link` symlink plus `os.Rename` swap and the `filepath.Rel(linkDir, target)` computation — removeDirContents() deletes the worktree but the link, or a copy of it, survives pointing at nothing, breaking the invariant that the link and its target are removed and restored atomically and yielding dangling link served to consumers: workload outage?

## Target
- File/function: [main.go](main.go) — `repoSync.publishSymlink`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Forces the root wipe path in initRepo() while the link is live. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: removeDirContents() deletes the worktree but the link, or a copy of it, survives pointing at nothing
- Invariant to test: the link and its target are removed and restored atomically
- Expected Immunefi impact: dangling link served to consumers: workload outage (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert every path git-sync creates under the link directory is owned by git-sync and not writable by other UIDs
