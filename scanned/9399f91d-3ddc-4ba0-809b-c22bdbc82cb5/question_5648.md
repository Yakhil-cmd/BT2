# Q5648: repoSync.sanityCheckRepo — disk full partial write under gc off

## Question
Starting from `--git-gc=off`, where objects are never collected, can an attacker who fills the volume with committed content so a later publish or cleanup hits ENOSPC drive sanityCheckRepo()/hasGitLockFile(), whose failure causes the entire root to be wiped to a state where the half-written state is neither published cleanly nor rolled back, and readiness still reports success, defeating “ENOSPC leaves a consistent, correctly-reported state” and causing silent serving of corrupt/partial content?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckRepo / hasGitLockFile`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Fills the volume with committed content so a later publish or cleanup hits ENOSPC. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the half-written state is neither published cleanly nor rolled back, and readiness still reports success
- Invariant to test: ENOSPC leaves a consistent, correctly-reported state
- Expected Immunefi impact: silent serving of corrupt/partial content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: force the failure condition and assert git-sync recovers without wiping already-published data
