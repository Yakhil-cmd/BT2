# Q2705: repoSync.cleanup — gc prunes live objects under gc off

## Question
Starting from `--git-gc=off`, where objects are never collected, can an attacker who arranges reachability so `reflog expire --expire-unreachable=all` plus gc removes objects backing the published worktree drive cleanup(): removeStaleWorktrees(), `worktree prune`, `reflog expire --expire-unreachable=all --all`, and the `gc` invocation to a state where the published tree loses its backing objects and later checks nuke it, defeating “objects backing published content are never collected” and causing published data destroyed mid-service?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Arranges reachability so `reflog expire --expire-unreachable=all` plus gc removes objects backing the published worktree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the published tree loses its backing objects and later checks nuke it
- Invariant to test: objects backing published content are never collected
- Expected Immunefi impact: published data destroyed mid-service (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: force the failure condition and assert git-sync recovers without wiping already-published data
