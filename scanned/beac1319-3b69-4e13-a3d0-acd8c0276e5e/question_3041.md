# Q3041: HookRunner.Run — onetime exit race under both hooks

## Question
Under a deployment using both exec and web hooks, an attacker makes the hook succeed for a stale hash in `--one-time` mode. In HookRunner.Run()'s retry loop, lastHash tracking, and the single-slot hookData channel, can that mean sendOneTimeResultAndTerminate() reports success and the process exits 0 while the published tree is not the validated one, so that the invariant “the one-time exit status reflects the published revision” no longer holds and the outcome is CI/init-container proceeding on unvalidated content?

## Target
- File/function: [pkg/hook/hook.go](pkg/hook/hook.go) — `HookRunner.Run / hookData.send`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the hook succeed for a stale hash in `--one-time` mode. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: sendOneTimeResultAndTerminate() reports success and the process exits 0 while the published tree is not the validated one
- Invariant to test: the one-time exit status reflects the published revision
- Expected Immunefi impact: CI/init-container proceeding on unvalidated content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
