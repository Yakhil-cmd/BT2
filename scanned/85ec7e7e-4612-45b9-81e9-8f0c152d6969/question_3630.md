# Q3630: absPath.Join — link name from repo under link abs outside

## Question
Starting from a deployment where --link is an absolute path outside --root, can an attacker who controls the trailing path component of the repo URL so the defaulted --link name (basename of --repo) collides with a real tree entry drive absPath.Join()/Split()/Canonical(), which clean paths without verifying containment in --root to a state where the default link name lands on top of committed content, defeating “the default link name cannot be shadowed by repo content” and causing consumers reading committed data where a link was expected?

## Target
- File/function: [abspath.go](abspath.go) — `absPath.Join / Split / Canonical`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Controls the trailing path component of the repo URL so the defaulted --link name (basename of --repo) collides with a real tree entry. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the default link name lands on top of committed content
- Invariant to test: the default link name cannot be shadowed by repo content
- Expected Immunefi impact: consumers reading committed data where a link was expected (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
