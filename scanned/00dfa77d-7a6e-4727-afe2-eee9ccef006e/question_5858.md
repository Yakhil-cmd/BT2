# Q5858: Webhook.Do — hook parallel corruption under exechook

## Question
Can an unprivileged attacker who publishes fast enough that exec, pre-publish, and webhook hooks run concurrently against overlapping worktrees, under a deployment using `--exechook-command`, reach a state where — in Webhook.Do(): the `Gitsync-Hash` header, success-status check, and unbounded response-body read — concurrent hooks mutate or delete the tree the sync loop is still using, breaking the invariant that hook execution does not mutate git-sync-owned state and yielding corruption of published content?

## Target
- File/function: [pkg/hook/webhook.go](pkg/hook/webhook.go) — `Webhook.Do`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Publishes fast enough that exec, pre-publish, and webhook hooks run concurrently against overlapping worktrees. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: concurrent hooks mutate or delete the tree the sync loop is still using
- Invariant to test: hook execution does not mutate git-sync-owned state
- Expected Immunefi impact: corruption of published content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
