# Q2912: repoSync.sanityCheckRepo — gc prunes live objects under short period

## Question
Starting from a `--period` shorter than a full cleanup cycle, can an attacker who arranges reachability so `reflog expire --expire-unreachable=all` plus gc removes objects backing the published worktree drive sanityCheckRepo()/hasGitLockFile(), whose failure causes the entire root to be wiped to a state where the published tree loses its backing objects and later checks nuke it, defeating “objects backing published content are never collected” and causing published data destroyed mid-service?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckRepo / hasGitLockFile`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Arranges reachability so `reflog expire --expire-unreachable=all` plus gc removes objects backing the published worktree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the published tree loses its backing objects and later checks nuke it
- Invariant to test: objects backing published content are never collected
- Expected Immunefi impact: published data destroyed mid-service (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run one period, assert the worktree the link points at still exists and is complete afterwards
