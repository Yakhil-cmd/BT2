# Q2375: runWithStdin — hook hash skipping under webhook

## Question
Can an unprivileged attacker who publishes several hashes faster than the hook completes, under a deployment using `--webhook-url`, reach a state where — in runWithStdin(): argv construction, env handling, output buffering, and cmdForLog()'s quoting for logs — the single-slot channel and lastHash logic silently skip intermediate hashes, so a hook meant to validate every revision never sees some, breaking the invariant that every published revision is observed by the hook, or skipping is surfaced and yielding bypass of a security-relevant post-sync validation step?

## Target
- File/function: [pkg/cmd/cmd.go](pkg/cmd/cmd.go) — `runWithStdin / cmdForLog`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Publishes several hashes faster than the hook completes. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the single-slot channel and lastHash logic silently skip intermediate hashes, so a hook meant to validate every revision never sees some
- Invariant to test: every published revision is observed by the hook, or skipping is surfaced
- Expected Immunefi impact: bypass of a security-relevant post-sync validation step (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: point the hook at a recorder script and assert it receives exactly one invocation per published hash with a validated hex GITSYNC_HASH
