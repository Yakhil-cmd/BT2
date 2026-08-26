# Q1985: repoSync.cleanup — fsck cost under gc always

## Question
Starting from `--git-gc=always`, can an attacker who pushes an object graph that makes `fsck --connectivity-only` extremely expensive drive cleanup(): removeStaleWorktrees(), `worktree prune`, `reflog expire --expire-unreachable=all --all`, and the `gc` invocation to a state where the sanity check dominates each period and pushes the sync past --sync-timeout, defeating “sanity-check cost is bounded relative to the sync budget” and causing permanent denial of updates?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Pushes an object graph that makes `fsck --connectivity-only` extremely expensive. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the sanity check dominates each period and pushes the sync past --sync-timeout
- Invariant to test: sanity-check cost is bounded relative to the sync budget
- Expected Immunefi impact: permanent denial of updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run one period, assert the worktree the link points at still exists and is complete afterwards
