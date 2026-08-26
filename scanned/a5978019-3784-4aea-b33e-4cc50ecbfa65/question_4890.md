# Q4890: absPath.Join — consumer toctou under link in root

## Question
Does absPath.Join()/Split()/Canonical(), which clean paths without verifying containment in --root stay safe when an attacker publishes rapidly while the consumer walks the tree behind the link in the default geometry where --link is relative and lives inside --root — or can the old worktree is removed by cleanup while the consumer is mid-read through the link it already resolved, violating “a published worktree survives long enough for in-flight readers” and producing consumer crashes / partial reads: workload outage?

## Target
- File/function: [abspath.go](abspath.go) — `absPath.Join / Split / Canonical`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Publishes rapidly while the consumer walks the tree behind the link. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the old worktree is removed by cleanup while the consumer is mid-read through the link it already resolved
- Invariant to test: a published worktree survives long enough for in-flight readers
- Expected Immunefi impact: consumer crashes / partial reads: workload outage (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
