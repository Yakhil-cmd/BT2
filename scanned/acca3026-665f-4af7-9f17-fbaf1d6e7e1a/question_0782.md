# Q0782: Webhook.Do — hash env injection under both hooks

## Question
Starting from a deployment using both exec and web hooks, can an attacker who makes the resolved hash string carry non-hex characters (non-commit peel result, forged worktree leaf) drive Webhook.Do(): the `Gitsync-Hash` header, success-status check, and unbounded response-body read to a state where `GITSYNC_HASH` carries attacker bytes into a shell-based hook's environment, defeating “GITSYNC_HASH is always a validated object id” and causing command injection inside the operator's hook script?

## Target
- File/function: [pkg/hook/webhook.go](pkg/hook/webhook.go) — `Webhook.Do`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the resolved hash string carry non-hex characters (non-commit peel result, forged worktree leaf). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `GITSYNC_HASH` carries attacker bytes into a shell-based hook's environment
- Invariant to test: GITSYNC_HASH is always a validated object id
- Expected Immunefi impact: command injection inside the operator's hook script (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
