# Q0671: removeDirContentsIf — stat skip hole under gc auto

## Question
Can an unprivileged attacker who creates entries under `.worktrees/` that fail `os.Stat` (dangling symlinks, EACCES paths) on a shared volume, under the default `--git-gc=auto`, reach a state where — in removeDirContentsIf(): the os.Stat + predicate + `os.RemoveAll` loop that wipes directory contents — removeDirContentsIf() logs and skips them forever, so they never get reclaimed, breaking the invariant that every entry under a git-sync-owned directory is reclaimable and yielding unbounded volume growth: node disk pressure?

## Target
- File/function: [main.go](main.go) — `removeDirContentsIf / removeDirContents`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Creates entries under `.worktrees/` that fail `os.Stat` (dangling symlinks, EACCES paths) on a shared volume. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: removeDirContentsIf() logs and skips them forever, so they never get reclaimed
- Invariant to test: every entry under a git-sync-owned directory is reclaimable
- Expected Immunefi impact: unbounded volume growth: node disk pressure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run one period, assert the worktree the link points at still exists and is complete afterwards
