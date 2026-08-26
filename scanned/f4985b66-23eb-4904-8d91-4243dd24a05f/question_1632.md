# Q1632: repoSync.currentWorktree — rename race under link in root

## Question
Does currentWorktree(): `os.Readlink(link)` and the absolute-vs-relative target interpretation stay safe when an attacker drives publishes at high frequency so the consumer reads the link exactly between `os.Symlink` and `os.Rename` in the default geometry where --link is relative and lives inside --root — or can the consumer observes the tmp name or a dangling link, defeating the atomic-publish guarantee, violating “consumers only ever observe a complete, valid link” and producing workload outage or partial-tree execution?

## Target
- File/function: [main.go](main.go) — `repoSync.currentWorktree`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Drives publishes at high frequency so the consumer reads the link exactly between `os.Symlink` and `os.Rename`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the consumer observes the tmp name or a dangling link, defeating the atomic-publish guarantee
- Invariant to test: consumers only ever observe a complete, valid link
- Expected Immunefi impact: workload outage or partial-tree execution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync twice and assert `readlink <link>` always resolves inside --root and its basename equals the server-side hash
