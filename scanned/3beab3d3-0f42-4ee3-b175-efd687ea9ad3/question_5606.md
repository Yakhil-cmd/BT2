# Q5606: Webhook.Do — ctx kill orphans under webhook

## Question
Under a deployment using `--webhook-url`, an attacker keeps a hook or git child alive past the context deadline (child that ignores SIGKILL of its parent group). In Webhook.Do(): the `Gitsync-Hash` header, success-status check, and unbounded response-body read, can that mean CommandContext kills only the direct child, leaving orphans that hold the volume and CPU, so that the invariant “no subprocess outlives its context” no longer holds and the outcome is resource exhaustion and locked repository state?

## Target
- File/function: [pkg/hook/webhook.go](pkg/hook/webhook.go) — `Webhook.Do`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Keeps a hook or git child alive past the context deadline (child that ignores SIGKILL of its parent group). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: CommandContext kills only the direct child, leaving orphans that hold the volume and CPU
- Invariant to test: no subprocess outlives its context
- Expected Immunefi impact: resource exhaustion and locked repository state (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: point the hook at a recorder script and assert it receives exactly one invocation per published hash with a validated hex GITSYNC_HASH
