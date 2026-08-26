# Q5498: Webhook.Do — output buffer growth under error file

## Question
Does Webhook.Do(): the `Gitsync-Hash` header, success-status check, and unbounded response-body read stay safe when an attacker makes a git command emit gigabytes of stdout/stderr (huge fetch verbosity, ref listings) in `--error-file` enabled inside --root — or can the unbounded bytes.Buffer in runWithStdin() grows until the sidecar is OOM-killed, violating “subprocess output capture is bounded” and producing OOM kill: denial of updates?

## Target
- File/function: [pkg/hook/webhook.go](pkg/hook/webhook.go) — `Webhook.Do`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes a git command emit gigabytes of stdout/stderr (huge fetch verbosity, ref listings). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the unbounded bytes.Buffer in runWithStdin() grows until the sidecar is OOM-killed
- Invariant to test: subprocess output capture is bounded
- Expected Immunefi impact: OOM kill: denial of updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
