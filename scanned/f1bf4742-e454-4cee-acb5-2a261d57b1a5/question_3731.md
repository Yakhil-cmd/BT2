# Q3731: removeDirContentsIf — worktree admin residue under stale timeout set

## Question
Under `--stale-worktree-timeout` set to a non-zero value, an attacker makes `worktree prune` leave `.git/worktrees/<hash>` entries that reference removed paths. In removeDirContentsIf(): the os.Stat + predicate + `os.RemoveAll` loop that wipes directory contents, can that mean later `worktree add` for the same hash fails, blocking republish of that revision, so that the invariant “administrative worktree state stays consistent with disk” no longer holds and the outcome is permanent denial of updates for a given revision?

## Target
- File/function: [main.go](main.go) — `removeDirContentsIf / removeDirContents`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Makes `worktree prune` leave `.git/worktrees/<hash>` entries that reference removed paths. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: later `worktree add` for the same hash fails, blocking republish of that revision
- Invariant to test: administrative worktree state stays consistent with disk
- Expected Immunefi impact: permanent denial of updates for a given revision (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: force the failure condition and assert git-sync recovers without wiping already-published data
