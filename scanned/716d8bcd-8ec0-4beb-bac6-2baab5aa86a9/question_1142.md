# Q1142: Webhook.Do — hash path injection under onetime

## Question
Under `--one-time` mode, where hook results gate the exit status, an attacker makes getWorktree(hash) return a path outside `.worktrees/` (via a forged link target). In Webhook.Do(): the `Gitsync-Hash` header, success-status check, and unbounded response-body read, can that mean the hook's cwd is an attacker-chosen directory, so that the invariant “hook cwd is always a git-sync-created worktree” no longer holds and the outcome is hook executing against attacker-controlled files?

## Target
- File/function: [pkg/hook/webhook.go](pkg/hook/webhook.go) — `Webhook.Do`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes getWorktree(hash) return a path outside `.worktrees/` (via a forged link target). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the hook's cwd is an attacker-chosen directory
- Invariant to test: hook cwd is always a git-sync-created worktree
- Expected Immunefi impact: hook executing against attacker-controlled files (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: point the hook at a recorder script and assert it receives exactly one invocation per published hash with a validated hex GITSYNC_HASH
