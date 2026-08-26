# Q1718: Webhook.Do — prepublish precheckout under webhook

## Question
Under a deployment using `--webhook-url`, an attacker times the push so the pre-publish hook runs against a worktree that is still being configured. In Webhook.Do(): the `Gitsync-Hash` header, success-status check, and unbounded response-body read, can that mean the hook sees a partial tree and its success gates a publish of different content, so that the invariant “the pre-publish hook observes exactly the tree that will be published” no longer holds and the outcome is unverified content published despite a gating hook?

## Target
- File/function: [pkg/hook/webhook.go](pkg/hook/webhook.go) — `Webhook.Do`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Times the push so the pre-publish hook runs against a worktree that is still being configured. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the hook sees a partial tree and its success gates a publish of different content
- Invariant to test: the pre-publish hook observes exactly the tree that will be published
- Expected Immunefi impact: unverified content published despite a gating hook (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: point the hook at a recorder script and assert it receives exactly one invocation per published hash with a validated hex GITSYNC_HASH
