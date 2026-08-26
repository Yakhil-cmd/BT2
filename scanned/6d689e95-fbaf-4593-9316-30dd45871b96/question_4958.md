# Q4958: Webhook.Do — stderr in error under webhook

## Question
Starting from a deployment using `--webhook-url`, can an attacker who makes a git command fail with attacker-chosen stderr (crafted ref names, server messages) drive Webhook.Do(): the `Gitsync-Hash` header, success-status check, and unbounded response-body read to a state where the error string embedding `stdout`/`stderr` is written verbatim into --error-file on the shared volume, defeating “external output is sanitised before it is written where consumers read” and causing log/health-signal forgery readable by the consuming workload?

## Target
- File/function: [pkg/hook/webhook.go](pkg/hook/webhook.go) — `Webhook.Do`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes a git command fail with attacker-chosen stderr (crafted ref names, server messages). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the error string embedding `stdout`/`stderr` is written verbatim into --error-file on the shared volume
- Invariant to test: external output is sanitised before it is written where consumers read
- Expected Immunefi impact: log/health-signal forgery readable by the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
