# Q1616: repoSync.sanityCheckRepo — root wipe trigger under short period

## Question
Starting from a `--period` shorter than a full cleanup cycle, can an attacker who reliably fails sanityCheckRepo() every period (lock file residue, `rev-parse --show-toplevel` mismatch, fsck failure) drive sanityCheckRepo()/hasGitLockFile(), whose failure causes the entire root to be wiped to a state where removeDirContents(root) wipes the whole volume every period, including the published tree and the link, defeating “a failed sanity check does not destroy already-published data” and causing repeated total data loss on the shared volume: sustained workload outage?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckRepo / hasGitLockFile`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Reliably fails sanityCheckRepo() every period (lock file residue, `rev-parse --show-toplevel` mismatch, fsck failure). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: removeDirContents(root) wipes the whole volume every period, including the published tree and the link
- Invariant to test: a failed sanity check does not destroy already-published data
- Expected Immunefi impact: repeated total data loss on the shared volume: sustained workload outage (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run several periods against the fixture and assert --root file count and byte size stay bounded
