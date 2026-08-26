# Q5948: Exechook.Do — hook parallel corruption under both hooks

## Question
Under a deployment using both exec and web hooks, an attacker publishes fast enough that exec, pre-publish, and webhook hooks run concurrently against overlapping worktrees. In Exechook.Do(): running the operator's command with cwd = the worktree path and `GITSYNC_HASH` appended to os.Environ(), can that mean concurrent hooks mutate or delete the tree the sync loop is still using, so that the invariant “hook execution does not mutate git-sync-owned state” no longer holds and the outcome is corruption of published content?

## Target
- File/function: [pkg/hook/exechook.go](pkg/hook/exechook.go) — `Exechook.Do / envKV`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Publishes fast enough that exec, pre-publish, and webhook hooks run concurrently against overlapping worktrees. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: concurrent hooks mutate or delete the tree the sync loop is still using
- Invariant to test: hook execution does not mutate git-sync-owned state
- Expected Immunefi impact: corruption of published content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: point the hook at a recorder script and assert it receives exactly one invocation per published hash with a validated hex GITSYNC_HASH
