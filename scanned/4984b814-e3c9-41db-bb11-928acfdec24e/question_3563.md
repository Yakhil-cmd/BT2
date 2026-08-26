# Q3563: runWithStdin — webhook ssrf body under error file

## Question
Under `--error-file` enabled inside --root, an attacker controls the webhook target's response (when the webhook URL points at an in-cluster endpoint the attacker can influence). In runWithStdin(): argv construction, env handling, output buffering, and cmdForLog()'s quoting for logs, can that mean the unbounded `io.ReadAll(resp.Body)` is logged in full at V(1) and on error, so that the invariant “response handling is size-bounded and never logs full bodies” no longer holds and the outcome is memory exhaustion and log poisoning?

## Target
- File/function: [pkg/cmd/cmd.go](pkg/cmd/cmd.go) — `runWithStdin / cmdForLog`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Controls the webhook target's response (when the webhook URL points at an in-cluster endpoint the attacker can influence). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the unbounded `io.ReadAll(resp.Body)` is logged in full at V(1) and on error
- Invariant to test: response handling is size-bounded and never logs full bodies
- Expected Immunefi impact: memory exhaustion and log poisoning (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: point the hook at a recorder script and assert it receives exactly one invocation per published hash with a validated hex GITSYNC_HASH
