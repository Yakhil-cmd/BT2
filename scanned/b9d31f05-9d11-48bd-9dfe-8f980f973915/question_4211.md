# Q4211: runWithStdin — webhook header forge under error file

## Question
Starting from `--error-file` enabled inside --root, can an attacker who makes the hash string carry header-invalid or control bytes into `req.Header.Set("Gitsync-Hash", hash)` drive runWithStdin(): argv construction, env handling, output buffering, and cmdForLog()'s quoting for logs to a state where the receiver is fed a forged or truncated revision identity, defeating “the hash header is always a validated object id” and causing downstream systems acting on a forged revision?

## Target
- File/function: [pkg/cmd/cmd.go](pkg/cmd/cmd.go) — `runWithStdin / cmdForLog`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the hash string carry header-invalid or control bytes into `req.Header.Set("Gitsync-Hash", hash)`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the receiver is fed a forged or truncated revision identity
- Invariant to test: the hash header is always a validated object id
- Expected Immunefi impact: downstream systems acting on a forged revision (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
