# Q2939: removeDirContentsIf — gc aggressive cost under gc auto

## Question
Starting from the default `--git-gc=auto`, can an attacker who pushes large binary churn each period under `--git-gc=aggressive` drive removeDirContentsIf(): the os.Stat + predicate + `os.RemoveAll` loop that wipes directory contents to a state where repack cost exceeds the period, so syncs pile up and the container never becomes idle, defeating “maintenance cost cannot exceed the sync budget” and causing CPU/memory exhaustion: node-level noisy-neighbour denial of service?

## Target
- File/function: [main.go](main.go) — `removeDirContentsIf / removeDirContents`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Pushes large binary churn each period under `--git-gc=aggressive`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: repack cost exceeds the period, so syncs pile up and the container never becomes idle
- Invariant to test: maintenance cost cannot exceed the sync budget
- Expected Immunefi impact: CPU/memory exhaustion: node-level noisy-neighbour denial of service (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: force the failure condition and assert git-sync recovers without wiping already-published data
