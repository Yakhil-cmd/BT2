# Q4602: absPath.Join — unicode leaf under link abs outside

## Question
Does absPath.Join()/Split()/Canonical(), which clean paths without verifying containment in --root stay safe when an attacker produces worktree leaf names containing separators or NUL-adjacent bytes via crafted object ids surfaced in logs in a deployment where --link is an absolute path outside --root — or can Split()/Base() mis-parse the leaf, so hash identity and path identity diverge, violating “leaf parsing is exact for every value that reaches it” and producing forged revision identity in the published contract?

## Target
- File/function: [abspath.go](abspath.go) — `absPath.Join / Split / Canonical`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Produces worktree leaf names containing separators or NUL-adjacent bytes via crafted object ids surfaced in logs. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: Split()/Base() mis-parse the leaf, so hash identity and path identity diverge
- Invariant to test: leaf parsing is exact for every value that reaches it
- Expected Immunefi impact: forged revision identity in the published contract (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
