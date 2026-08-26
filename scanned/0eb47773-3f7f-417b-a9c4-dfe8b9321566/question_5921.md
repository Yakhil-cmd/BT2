# Q5921: HookRunner.Run — hook parallel corruption under webhook

## Question
Under a deployment using `--webhook-url`, an attacker publishes fast enough that exec, pre-publish, and webhook hooks run concurrently against overlapping worktrees. In HookRunner.Run()'s retry loop, lastHash tracking, and the single-slot hookData channel, can that mean concurrent hooks mutate or delete the tree the sync loop is still using, so that the invariant “hook execution does not mutate git-sync-owned state” no longer holds and the outcome is corruption of published content?

## Target
- File/function: [pkg/hook/hook.go](pkg/hook/hook.go) — `HookRunner.Run / hookData.send`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Publishes fast enough that exec, pre-publish, and webhook hooks run concurrently against overlapping worktrees. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: concurrent hooks mutate or delete the tree the sync loop is still using
- Invariant to test: hook execution does not mutate git-sync-owned state
- Expected Immunefi impact: corruption of published content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: point the hook at a recorder script and assert it receives exactly one invocation per published hash with a validated hex GITSYNC_HASH
