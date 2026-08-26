# Q3338: Webhook.Do — webhook ssrf body under webhook

## Question
Does Webhook.Do(): the `Gitsync-Hash` header, success-status check, and unbounded response-body read stay safe when an attacker controls the webhook target's response (when the webhook URL points at an in-cluster endpoint the attacker can influence) in a deployment using `--webhook-url` — or can the unbounded `io.ReadAll(resp.Body)` is logged in full at V(1) and on error, violating “response handling is size-bounded and never logs full bodies” and producing memory exhaustion and log poisoning?

## Target
- File/function: [pkg/hook/webhook.go](pkg/hook/webhook.go) — `Webhook.Do`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Controls the webhook target's response (when the webhook URL points at an in-cluster endpoint the attacker can influence). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the unbounded `io.ReadAll(resp.Body)` is logged in full at V(1) and on error
- Invariant to test: response handling is size-bounded and never logs full bodies
- Expected Immunefi impact: memory exhaustion and log poisoning (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
