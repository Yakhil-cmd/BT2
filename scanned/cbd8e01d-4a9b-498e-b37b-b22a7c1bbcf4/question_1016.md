# Q1016: Exechook.Do — hash path injection under prepub hook

## Question
Can an unprivileged attacker who makes getWorktree(hash) return a path outside `.worktrees/` (via a forged link target), under a deployment using `--pre-publish-exechook-command`, reach a state where — in Exechook.Do(): running the operator's command with cwd = the worktree path and `GITSYNC_HASH` appended to os.Environ() — the hook's cwd is an attacker-chosen directory, breaking the invariant that hook cwd is always a git-sync-created worktree and yielding hook executing against attacker-controlled files?

## Target
- File/function: [pkg/hook/exechook.go](pkg/hook/exechook.go) — `Exechook.Do / envKV`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes getWorktree(hash) return a path outside `.worktrees/` (via a forged link target). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the hook's cwd is an attacker-chosen directory
- Invariant to test: hook cwd is always a git-sync-created worktree
- Expected Immunefi impact: hook executing against attacker-controlled files (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
