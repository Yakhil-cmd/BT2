# Q3842: Webhook.Do — webhook body oom under shared volume

## Question
Can an unprivileged attacker who makes the webhook endpoint stream an endless body, under a shared volume where hook output lands next to consumer data, reach a state where — in Webhook.Do(): the `Gitsync-Hash` header, success-status check, and unbounded response-body read — io.ReadAll grows without limit inside the sidecar, breaking the invariant that webhook responses are size-capped and yielding OOM kill of the sidecar: denial of updates?

## Target
- File/function: [pkg/hook/webhook.go](pkg/hook/webhook.go) — `Webhook.Do`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the webhook endpoint stream an endless body. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: io.ReadAll grows without limit inside the sidecar
- Invariant to test: webhook responses are size-capped
- Expected Immunefi impact: OOM kill of the sidecar: denial of updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
