# Q2006: Webhook.Do — hook retry storm under prepub hook

## Question
Under a deployment using `--pre-publish-exechook-command`, an attacker makes the hook fail deterministically (content the hook rejects). In Webhook.Do(): the `Gitsync-Hash` header, success-status check, and unbounded response-body read, can that mean HookRunner.Run() retries forever at --exechook-backoff while the sync loop keeps publishing, so that the invariant “hook failure is bounded and surfaced” no longer holds and the outcome is resource exhaustion plus silent divergence between published and hook-validated state?

## Target
- File/function: [pkg/hook/webhook.go](pkg/hook/webhook.go) — `Webhook.Do`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the hook fail deterministically (content the hook rejects). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: HookRunner.Run() retries forever at --exechook-backoff while the sync loop keeps publishing
- Invariant to test: hook failure is bounded and surfaced
- Expected Immunefi impact: resource exhaustion plus silent divergence between published and hook-validated state (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: point the hook at a recorder script and assert it receives exactly one invocation per published hash with a validated hex GITSYNC_HASH
