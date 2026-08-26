# Q4523: removeDirContentsIf — multierror masking under short period

## Question
Starting from a `--period` shorter than a full cleanup cycle, can an attacker who makes several cleanup steps fail at once drive removeDirContentsIf(): the os.Stat + predicate + `os.RemoveAll` loop that wipes directory contents to a state where multiError aggregation logs but does not stop the loop, so failures are invisible while the volume fills, defeating “repeated cleanup failure is escalated, not merely logged” and causing silent volume exhaustion ending in node disk pressure?

## Target
- File/function: [main.go](main.go) — `removeDirContentsIf / removeDirContents`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Makes several cleanup steps fail at once. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: multiError aggregation logs but does not stop the loop, so failures are invisible while the volume fills
- Invariant to test: repeated cleanup failure is escalated, not merely logged
- Expected Immunefi impact: silent volume exhaustion ending in node disk pressure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: force the failure condition and assert git-sync recovers without wiping already-published data
