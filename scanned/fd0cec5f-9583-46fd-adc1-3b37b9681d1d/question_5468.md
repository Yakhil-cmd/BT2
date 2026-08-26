# Q5468: repoSync.sanityCheckRepo — reflog expire cost under small volume

## Question
Does sanityCheckRepo()/hasGitLockFile(), whose failure causes the entire root to be wiped stay safe when an attacker pushes enough refs to make `reflog expire --all` take longer than the period in a small emptyDir sized for one checkout — or can cleanup consumes the whole period, starving fetch and publish, violating “maintenance cannot starve the sync loop” and producing permanent denial of updates?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckRepo / hasGitLockFile`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Pushes enough refs to make `reflog expire --all` take longer than the period. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: cleanup consumes the whole period, starving fetch and publish
- Invariant to test: maintenance cannot starve the sync loop
- Expected Immunefi impact: permanent denial of updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: force the failure condition and assert git-sync recovers without wiping already-published data
