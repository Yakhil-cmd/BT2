# Q5849: HookRunner.Run — hook parallel corruption under exechook

## Question
Starting from a deployment using `--exechook-command`, can an attacker who publishes fast enough that exec, pre-publish, and webhook hooks run concurrently against overlapping worktrees drive HookRunner.Run()'s retry loop, lastHash tracking, and the single-slot hookData channel to a state where concurrent hooks mutate or delete the tree the sync loop is still using, defeating “hook execution does not mutate git-sync-owned state” and causing corruption of published content?

## Target
- File/function: [pkg/hook/hook.go](pkg/hook/hook.go) — `HookRunner.Run / hookData.send`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Publishes fast enough that exec, pre-publish, and webhook hooks run concurrently against overlapping worktrees. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: concurrent hooks mutate or delete the tree the sync loop is still using
- Invariant to test: hook execution does not mutate git-sync-owned state
- Expected Immunefi impact: corruption of published content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
