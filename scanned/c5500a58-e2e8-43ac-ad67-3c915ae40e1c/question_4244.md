# Q4244: repoSync.sanityCheckRepo — multierror masking under gc auto

## Question
Can an unprivileged attacker who makes several cleanup steps fail at once, under the default `--git-gc=auto`, reach a state where — in sanityCheckRepo()/hasGitLockFile(), whose failure causes the entire root to be wiped — multiError aggregation logs but does not stop the loop, so failures are invisible while the volume fills, breaking the invariant that repeated cleanup failure is escalated, not merely logged and yielding silent volume exhaustion ending in node disk pressure?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckRepo / hasGitLockFile`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Makes several cleanup steps fail at once. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: multiError aggregation logs but does not stop the loop, so failures are invisible while the volume fills
- Invariant to test: repeated cleanup failure is escalated, not merely logged
- Expected Immunefi impact: silent volume exhaustion ending in node disk pressure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run one period, assert the worktree the link points at still exists and is complete afterwards
