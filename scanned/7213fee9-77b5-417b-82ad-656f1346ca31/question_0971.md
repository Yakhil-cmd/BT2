# Q0971: runWithStdin — hash env injection under error file

## Question
Under `--error-file` enabled inside --root, an attacker makes the resolved hash string carry non-hex characters (non-commit peel result, forged worktree leaf). In runWithStdin(): argv construction, env handling, output buffering, and cmdForLog()'s quoting for logs, can that mean `GITSYNC_HASH` carries attacker bytes into a shell-based hook's environment, so that the invariant “GITSYNC_HASH is always a validated object id” no longer holds and the outcome is command injection inside the operator's hook script?

## Target
- File/function: [pkg/cmd/cmd.go](pkg/cmd/cmd.go) — `runWithStdin / cmdForLog`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the resolved hash string carry non-hex characters (non-commit peel result, forged worktree leaf). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `GITSYNC_HASH` carries attacker bytes into a shell-based hook's environment
- Invariant to test: GITSYNC_HASH is always a validated object id
- Expected Immunefi impact: command injection inside the operator's hook script (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
