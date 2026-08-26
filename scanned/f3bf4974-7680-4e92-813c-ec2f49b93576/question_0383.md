# Q0383: removeDirContentsIf — mtime manipulation under gc always

## Question
Can an unprivileged attacker who controls file mtimes in the published tree (committed timestamps, or touch via the shared volume) so `.worktrees/<hash>` looks older than --stale-worktree-timeout, under `--git-gc=always`, reach a state where — in removeDirContentsIf(): the os.Stat + predicate + `os.RemoveAll` loop that wipes directory contents — a live-but-not-current worktree that in-flight consumers still hold is reclaimed early, breaking the invariant that staleness is measured from publish time, not from attacker-influenceable metadata and yielding partial reads/outage for consumers holding an older tree?

## Target
- File/function: [main.go](main.go) — `removeDirContentsIf / removeDirContents`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Controls file mtimes in the published tree (committed timestamps, or touch via the shared volume) so `.worktrees/<hash>` looks older than --stale-worktree-timeout. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: a live-but-not-current worktree that in-flight consumers still hold is reclaimed early
- Invariant to test: staleness is measured from publish time, not from attacker-influenceable metadata
- Expected Immunefi impact: partial reads/outage for consumers holding an older tree (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run one period, assert the worktree the link points at still exists and is complete afterwards
