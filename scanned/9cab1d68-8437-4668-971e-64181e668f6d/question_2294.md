# Q2294: Webhook.Do — hook hash skipping under exechook

## Question
Under a deployment using `--exechook-command`, an attacker publishes several hashes faster than the hook completes. In Webhook.Do(): the `Gitsync-Hash` header, success-status check, and unbounded response-body read, can that mean the single-slot channel and lastHash logic silently skip intermediate hashes, so a hook meant to validate every revision never sees some, so that the invariant “every published revision is observed by the hook, or skipping is surfaced” no longer holds and the outcome is bypass of a security-relevant post-sync validation step?

## Target
- File/function: [pkg/hook/webhook.go](pkg/hook/webhook.go) — `Webhook.Do`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Publishes several hashes faster than the hook completes. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the single-slot channel and lastHash logic silently skip intermediate hashes, so a hook meant to validate every revision never sees some
- Invariant to test: every published revision is observed by the hook, or skipping is surfaced
- Expected Immunefi impact: bypass of a security-relevant post-sync validation step (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: point the hook at a recorder script and assert it receives exactly one invocation per published hash with a validated hex GITSYNC_HASH
