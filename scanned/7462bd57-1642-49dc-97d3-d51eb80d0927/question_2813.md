# Q2813: repoSync.cleanup — gc prunes live objects under shared volume

## Question
Does cleanup(): removeStaleWorktrees(), `worktree prune`, `reflog expire --expire-unreachable=all --all`, and the `gc` invocation stay safe when an attacker arranges reachability so `reflog expire --expire-unreachable=all` plus gc removes objects backing the published worktree in a shared volume that a co-tenant container can also write into — or can the published tree loses its backing objects and later checks nuke it, violating “objects backing published content are never collected” and producing published data destroyed mid-service?

## Target
- File/function: [main.go](main.go) — `repoSync.cleanup`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Arranges reachability so `reflog expire --expire-unreachable=all` plus gc removes objects backing the published worktree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the published tree loses its backing objects and later checks nuke it
- Invariant to test: objects backing published content are never collected
- Expected Immunefi impact: published data destroyed mid-service (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: force the failure condition and assert git-sync recovers without wiping already-published data
