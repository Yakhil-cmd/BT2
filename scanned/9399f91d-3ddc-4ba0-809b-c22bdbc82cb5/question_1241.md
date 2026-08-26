# Q1241: HookRunner.Run — hash path injection under shared volume

## Question
Starting from a shared volume where hook output lands next to consumer data, can an attacker who makes getWorktree(hash) return a path outside `.worktrees/` (via a forged link target) drive HookRunner.Run()'s retry loop, lastHash tracking, and the single-slot hookData channel to a state where the hook's cwd is an attacker-chosen directory, defeating “hook cwd is always a git-sync-created worktree” and causing hook executing against attacker-controlled files?

## Target
- File/function: [pkg/hook/hook.go](pkg/hook/hook.go) — `HookRunner.Run / hookData.send`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes getWorktree(hash) return a path outside `.worktrees/` (via a forged link target). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the hook's cwd is an attacker-chosen directory
- Invariant to test: hook cwd is always a git-sync-created worktree
- Expected Immunefi impact: hook executing against attacker-controlled files (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
