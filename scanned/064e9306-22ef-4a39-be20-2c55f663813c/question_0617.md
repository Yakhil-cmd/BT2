# Q0617: repoSync.cleanup — mtime manipulation under short period

## Question
Under a `--period` shorter than a full cleanup cycle, an attacker controls file mtimes in the published tree (committed timestamps, or touch via the shared volume) so `.worktrees/<hash>` looks older than --stale-worktree-timeout. In cleanup(): removeStaleWorktrees(), `worktree prune`, `reflog expire --expire-unreachable=all --all`, and the `gc` invocation, can that mean a live-but-not-current worktree that in-flight consumers still hold is reclaimed early, so that the invariant “staleness is measured from publish time, not from attacker-influenceable metadata” no longer holds and the outcome is partial reads/outage for consumers holding an older tree?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Controls file mtimes in the published tree (committed timestamps, or touch via the shared volume) so `.worktrees/<hash>` looks older than --stale-worktree-timeout. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a live-but-not-current worktree that in-flight consumers still hold is reclaimed early
- Invariant to test: staleness is measured from publish time, not from attacker-influenceable metadata
- Expected Immunefi impact: partial reads/outage for consumers holding an older tree (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run several periods against the fixture and assert --root file count and byte size stay bounded
