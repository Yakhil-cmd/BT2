# Q1731: repoSync.publishSymlink — rename race under shared volume

## Question
Can an unprivileged attacker who drives publishes at high frequency so the consumer reads the link exactly between `os.Symlink` and `os.Rename`, under a shared volume readable and traversable by a co-tenant container, reach a state where — in publishSymlink(): the `tmp-link` symlink plus `os.Rename` swap and the `filepath.Rel(linkDir, target)` computation — the consumer observes the tmp name or a dangling link, defeating the atomic-publish guarantee, breaking the invariant that consumers only ever observe a complete, valid link and yielding workload outage or partial-tree execution?

## Target
- File/function: [main.go](main.go) — `repoSync.publishSymlink`
- Entrypoint: attacker push (or co-tenant write on the shared --root volume) -> publishSymlink()/currentWorktree() on the next sync
- Attacker controls: Drives publishes at high frequency so the consumer reads the link exactly between `os.Symlink` and `os.Rename`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the consumer observes the tmp name or a dangling link, defeating the atomic-publish guarantee
- Invariant to test: consumers only ever observe a complete, valid link
- Expected Immunefi impact: workload outage or partial-tree execution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert every path git-sync creates under the link directory is owned by git-sync and not writable by other UIDs
