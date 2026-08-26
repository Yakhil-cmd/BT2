# Q3603: repoSync.publishSymlink — link name from repo under link abs outside

## Question
Can an unprivileged attacker who controls the trailing path component of the repo URL so the defaulted --link name (basename of --repo) collides with a real tree entry, under a deployment where --link is an absolute path outside --root, reach a state where — in publishSymlink(): the `tmp-link` symlink plus `os.Rename` swap and the `filepath.Rel(linkDir, target)` computation — the default link name lands on top of committed content, breaking the invariant that the default link name cannot be shadowed by repo content and yielding consumers reading committed data where a link was expected?

## Target
- File/function: [main.go](main.go) — `repoSync.publishSymlink`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Controls the trailing path component of the repo URL so the defaulted --link name (basename of --repo) collides with a real tree entry. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the default link name lands on top of committed content
- Invariant to test: the default link name cannot be shadowed by repo content
- Expected Immunefi impact: consumers reading committed data where a link was expected (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
