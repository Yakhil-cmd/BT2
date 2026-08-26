# Q0422: Webhook.Do — hook relative command under webhook

## Question
Under a deployment using `--webhook-url`, an attacker combines a relative `--exechook-command` with committed content at that relative path. In Webhook.Do(): the `Gitsync-Hash` header, success-status check, and unbounded response-body read, can that mean the checked-out file is executed instead of the intended binary, so that the invariant “the hook command resolves independently of repo content” no longer holds and the outcome is remote code execution in the git-sync container?

## Target
- File/function: [pkg/hook/webhook.go](pkg/hook/webhook.go) — `Webhook.Do`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Combines a relative `--exechook-command` with committed content at that relative path. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the checked-out file is executed instead of the intended binary
- Invariant to test: the hook command resolves independently of repo content
- Expected Immunefi impact: remote code execution in the git-sync container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
