# Q5106: absPath.Join — consumer toctou under stale timeout

## Question
Can an unprivileged attacker who publishes rapidly while the consumer walks the tree behind the link, under `--stale-worktree-timeout` set, so previous worktrees linger, reach a state where — in absPath.Join()/Split()/Canonical(), which clean paths without verifying containment in --root — the old worktree is removed by cleanup while the consumer is mid-read through the link it already resolved, breaking the invariant that a published worktree survives long enough for in-flight readers and yielding consumer crashes / partial reads: workload outage?

## Target
- File/function: [abspath.go](abspath.go) — `absPath.Join / Split / Canonical`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Publishes rapidly while the consumer walks the tree behind the link. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the old worktree is removed by cleanup while the consumer is mid-read through the link it already resolved
- Invariant to test: a published worktree survives long enough for in-flight readers
- Expected Immunefi impact: consumer crashes / partial reads: workload outage (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
