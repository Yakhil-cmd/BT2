# Q1025: HookRunner.Run — hash path injection under prepub hook

## Question
Under a deployment using `--pre-publish-exechook-command`, an attacker makes getWorktree(hash) return a path outside `.worktrees/` (via a forged link target). In HookRunner.Run()'s retry loop, lastHash tracking, and the single-slot hookData channel, can that mean the hook's cwd is an attacker-chosen directory, so that the invariant “hook cwd is always a git-sync-created worktree” no longer holds and the outcome is hook executing against attacker-controlled files?

## Target
- File/function: [pkg/hook/hook.go](pkg/hook/hook.go) — `HookRunner.Run / hookData.send`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes getWorktree(hash) return a path outside `.worktrees/` (via a forged link target). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the hook's cwd is an attacker-chosen directory
- Invariant to test: hook cwd is always a git-sync-created worktree
- Expected Immunefi impact: hook executing against attacker-controlled files (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
