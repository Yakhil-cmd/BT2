# Q2264: repoSync.sanityCheckRepo — fsck cost under short period

## Question
Under a `--period` shorter than a full cleanup cycle, an attacker pushes an object graph that makes `fsck --connectivity-only` extremely expensive. In sanityCheckRepo()/hasGitLockFile(), whose failure causes the entire root to be wiped, can that mean the sanity check dominates each period and pushes the sync past --sync-timeout, so that the invariant “sanity-check cost is bounded relative to the sync budget” no longer holds and the outcome is permanent denial of updates?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckRepo / hasGitLockFile`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Pushes an object graph that makes `fsck --connectivity-only` extremely expensive. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the sanity check dominates each period and pushes the sync past --sync-timeout
- Invariant to test: sanity-check cost is bounded relative to the sync budget
- Expected Immunefi impact: permanent denial of updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: force the failure condition and assert git-sync recovers without wiping already-published data
