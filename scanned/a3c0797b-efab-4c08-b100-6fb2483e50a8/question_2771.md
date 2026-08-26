# Q2771: runWithStdin — hook stale hash under onetime

## Question
Starting from `--one-time` mode, where hook results gate the exit status, can an attacker who forces a failure right after Send() so the retry re-reads the newest hash drive runWithStdin(): argv construction, env handling, output buffering, and cmdForLog()'s quoting for logs to a state where the hook runs against a hash whose worktree was already reclaimed, defeating “the hook always runs against a live worktree” and causing hook operating on a deleted path: failed validation or wrong-tree action?

## Target
- File/function: [pkg/cmd/cmd.go](pkg/cmd/cmd.go) — `runWithStdin / cmdForLog`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Forces a failure right after Send() so the retry re-reads the newest hash. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the hook runs against a hash whose worktree was already reclaimed
- Invariant to test: the hook always runs against a live worktree
- Expected Immunefi impact: hook operating on a deleted path: failed validation or wrong-tree action (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: point the hook at a recorder script and assert it receives exactly one invocation per published hash with a validated hex GITSYNC_HASH
