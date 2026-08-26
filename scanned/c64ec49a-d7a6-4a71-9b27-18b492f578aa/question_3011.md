# Q3011: removeDirContentsIf — gc aggressive cost under gc aggressive

## Question
Under `--git-gc=aggressive`, an attacker pushes large binary churn each period under `--git-gc=aggressive`. In removeDirContentsIf(): the os.Stat + predicate + `os.RemoveAll` loop that wipes directory contents, can that mean repack cost exceeds the period, so syncs pile up and the container never becomes idle, so that the invariant “maintenance cost cannot exceed the sync budget” no longer holds and the outcome is CPU/memory exhaustion: node-level noisy-neighbour denial of service?

## Target
- File/function: [main.go](main.go) — `removeDirContentsIf / removeDirContents`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Pushes large binary churn each period under `--git-gc=aggressive`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: repack cost exceeds the period, so syncs pile up and the container never becomes idle
- Invariant to test: maintenance cost cannot exceed the sync budget
- Expected Immunefi impact: CPU/memory exhaustion: node-level noisy-neighbour denial of service (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run one period, assert the worktree the link points at still exists and is complete afterwards
