# Q2766: absPath.Join — stale link after wipe under group write

## Question
Starting from `--group-write` enabled, so the umask is 0002, can an attacker who forces the root wipe path in initRepo() while the link is live drive absPath.Join()/Split()/Canonical(), which clean paths without verifying containment in --root to a state where removeDirContents() deletes the worktree but the link, or a copy of it, survives pointing at nothing, defeating “the link and its target are removed and restored atomically” and causing dangling link served to consumers: workload outage?

## Target
- File/function: [abspath.go](abspath.go) — `absPath.Join / Split / Canonical`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Forces the root wipe path in initRepo() while the link is live. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: removeDirContents() deletes the worktree but the link, or a copy of it, survives pointing at nothing
- Invariant to test: the link and its target are removed and restored atomically
- Expected Immunefi impact: dangling link served to consumers: workload outage (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
