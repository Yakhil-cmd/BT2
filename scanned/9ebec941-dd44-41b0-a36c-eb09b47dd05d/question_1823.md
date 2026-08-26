# Q1823: removeDirContentsIf — toplevel mismatch under stale timeout zero

## Question
Can an unprivileged attacker who arranges a nested `.git` (committed or via a shared-volume path) so `rev-parse --show-toplevel` reports a parent repo, under the default zero `--stale-worktree-timeout`, where non-current worktrees are reclaimed immediately, reach a state where — in removeDirContentsIf(): the os.Stat + predicate + `os.RemoveAll` loop that wipes directory contents — sanityCheckRepo() concludes the root is under another repo and wipes it, breaking the invariant that toplevel detection cannot be influenced by repo content or volume neighbours and yielding total wipe of the published volume on every sync?

## Target
- File/function: [main.go](main.go) — `removeDirContentsIf / removeDirContents`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Arranges a nested `.git` (committed or via a shared-volume path) so `rev-parse --show-toplevel` reports a parent repo. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: sanityCheckRepo() concludes the root is under another repo and wipes it
- Invariant to test: toplevel detection cannot be influenced by repo content or volume neighbours
- Expected Immunefi impact: total wipe of the published volume on every sync (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run several periods against the fixture and assert --root file count and byte size stay bounded
