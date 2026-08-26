# Q2078: Webhook.Do — hook retry storm under both hooks

## Question
Starting from a deployment using both exec and web hooks, can an attacker who makes the hook fail deterministically (content the hook rejects) drive Webhook.Do(): the `Gitsync-Hash` header, success-status check, and unbounded response-body read to a state where HookRunner.Run() retries forever at --exechook-backoff while the sync loop keeps publishing, defeating “hook failure is bounded and surfaced” and causing resource exhaustion plus silent divergence between published and hook-validated state?

## Target
- File/function: [pkg/hook/webhook.go](pkg/hook/webhook.go) — `Webhook.Do`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the hook fail deterministically (content the hook rejects). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: HookRunner.Run() retries forever at --exechook-backoff while the sync loop keeps publishing
- Invariant to test: hook failure is bounded and surfaced
- Expected Immunefi impact: resource exhaustion plus silent divergence between published and hook-validated state (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
