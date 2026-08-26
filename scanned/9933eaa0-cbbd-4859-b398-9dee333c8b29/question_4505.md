# Q4505: repoSync.cleanup — multierror masking under short period

## Question
Under a `--period` shorter than a full cleanup cycle, an attacker makes several cleanup steps fail at once. In cleanup(): removeStaleWorktrees(), `worktree prune`, `reflog expire --expire-unreachable=all --all`, and the `gc` invocation, can that mean multiError aggregation logs but does not stop the loop, so failures are invisible while the volume fills, so that the invariant “repeated cleanup failure is escalated, not merely logged” no longer holds and the outcome is silent volume exhaustion ending in node disk pressure?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Makes several cleanup steps fail at once. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: multiError aggregation logs but does not stop the loop, so failures are invisible while the volume fills
- Invariant to test: repeated cleanup failure is escalated, not merely logged
- Expected Immunefi impact: silent volume exhaustion ending in node disk pressure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run several periods against the fixture and assert --root file count and byte size stay bounded
