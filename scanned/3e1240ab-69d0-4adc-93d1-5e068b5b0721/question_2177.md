# Q2177: HookRunner.Run — hook retry storm under short period

## Question
Under a `--period` shorter than the hook's runtime, an attacker makes the hook fail deterministically (content the hook rejects). In HookRunner.Run()'s retry loop, lastHash tracking, and the single-slot hookData channel, can that mean HookRunner.Run() retries forever at --exechook-backoff while the sync loop keeps publishing, so that the invariant “hook failure is bounded and surfaced” no longer holds and the outcome is resource exhaustion plus silent divergence between published and hook-validated state?

## Target
- File/function: [pkg/hook/hook.go](pkg/hook/hook.go) — `HookRunner.Run / hookData.send`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the hook fail deterministically (content the hook rejects). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: HookRunner.Run() retries forever at --exechook-backoff while the sync loop keeps publishing
- Invariant to test: hook failure is bounded and surfaced
- Expected Immunefi impact: resource exhaustion plus silent divergence between published and hook-validated state (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
