# Q2141: HookRunner.Run — hook retry storm under short backoff

## Question
Can an unprivileged attacker who makes the hook fail deterministically (content the hook rejects), under the minimum 1s hook backoff, reach a state where — in HookRunner.Run()'s retry loop, lastHash tracking, and the single-slot hookData channel — HookRunner.Run() retries forever at --exechook-backoff while the sync loop keeps publishing, breaking the invariant that hook failure is bounded and surfaced and yielding resource exhaustion plus silent divergence between published and hook-validated state?

## Target
- File/function: [pkg/hook/hook.go](pkg/hook/hook.go) — `HookRunner.Run / hookData.send`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the hook fail deterministically (content the hook rejects). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: HookRunner.Run() retries forever at --exechook-backoff while the sync loop keeps publishing
- Invariant to test: hook failure is bounded and surfaced
- Expected Immunefi impact: resource exhaustion plus silent divergence between published and hook-validated state (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: point the hook at a recorder script and assert it receives exactly one invocation per published hash with a validated hex GITSYNC_HASH
