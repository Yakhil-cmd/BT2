# Q1938: absPath.Join — rename race under error file

## Question
Can an unprivileged attacker who drives publishes at high frequency so the consumer reads the link exactly between `os.Symlink` and `os.Rename`, under a deployment using `--error-file` inside --root, reach a state where — in absPath.Join()/Split()/Canonical(), which clean paths without verifying containment in --root — the consumer observes the tmp name or a dangling link, defeating the atomic-publish guarantee, breaking the invariant that consumers only ever observe a complete, valid link and yielding workload outage or partial-tree execution?

## Target
- File/function: [abspath.go](abspath.go) — `absPath.Join / Split / Canonical`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Drives publishes at high frequency so the consumer reads the link exactly between `os.Symlink` and `os.Rename`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the consumer observes the tmp name or a dangling link, defeating the atomic-publish guarantee
- Invariant to test: consumers only ever observe a complete, valid link
- Expected Immunefi impact: workload outage or partial-tree execution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: loop a reader on the link while syncing rapidly and assert it never observes a dangling or `tmp-link` path
