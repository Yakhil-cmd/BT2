# Q0719: runWithStdin — hash env injection under prepub hook

## Question
Does runWithStdin(): argv construction, env handling, output buffering, and cmdForLog()'s quoting for logs stay safe when an attacker makes the resolved hash string carry non-hex characters (non-commit peel result, forged worktree leaf) in a deployment using `--pre-publish-exechook-command` — or can `GITSYNC_HASH` carries attacker bytes into a shell-based hook's environment, violating “GITSYNC_HASH is always a validated object id” and producing command injection inside the operator's hook script?

## Target
- File/function: [pkg/cmd/cmd.go](pkg/cmd/cmd.go) — `runWithStdin / cmdForLog`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the resolved hash string carry non-hex characters (non-commit peel result, forged worktree leaf). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `GITSYNC_HASH` carries attacker bytes into a shell-based hook's environment
- Invariant to test: GITSYNC_HASH is always a validated object id
- Expected Immunefi impact: command injection inside the operator's hook script (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: point the hook at a recorder script and assert it receives exactly one invocation per published hash with a validated hex GITSYNC_HASH
