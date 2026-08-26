# Q3236: repoSync.sanityCheckRepo — gc aggressive cost under short period

## Question
Can an unprivileged attacker who pushes large binary churn each period under `--git-gc=aggressive`, under a `--period` shorter than a full cleanup cycle, reach a state where — in sanityCheckRepo()/hasGitLockFile(), whose failure causes the entire root to be wiped — repack cost exceeds the period, so syncs pile up and the container never becomes idle, breaking the invariant that maintenance cost cannot exceed the sync budget and yielding CPU/memory exhaustion: node-level noisy-neighbour denial of service?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckRepo / hasGitLockFile`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Pushes large binary churn each period under `--git-gc=aggressive`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: repack cost exceeds the period, so syncs pile up and the container never becomes idle
- Invariant to test: maintenance cost cannot exceed the sync budget
- Expected Immunefi impact: CPU/memory exhaustion: node-level noisy-neighbour denial of service (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: force the failure condition and assert git-sync recovers without wiping already-published data
