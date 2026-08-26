# Q4985: HookRunner.Run — stderr in error under both hooks

## Question
Starting from a deployment using both exec and web hooks, can an attacker who makes a git command fail with attacker-chosen stderr (crafted ref names, server messages) drive HookRunner.Run()'s retry loop, lastHash tracking, and the single-slot hookData channel to a state where the error string embedding `stdout`/`stderr` is written verbatim into --error-file on the shared volume, defeating “external output is sanitised before it is written where consumers read” and causing log/health-signal forgery readable by the consuming workload?

## Target
- File/function: [pkg/hook/hook.go](pkg/hook/hook.go) — `HookRunner.Run / hookData.send`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes a git command fail with attacker-chosen stderr (crafted ref names, server messages). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the error string embedding `stdout`/`stderr` is written verbatim into --error-file on the shared volume
- Invariant to test: external output is sanitised before it is written where consumers read
- Expected Immunefi impact: log/health-signal forgery readable by the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
