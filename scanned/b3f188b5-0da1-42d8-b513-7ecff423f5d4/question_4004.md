# Q4004: Exechook.Do — webhook header forge under both hooks

## Question
Starting from a deployment using both exec and web hooks, can an attacker who makes the hash string carry header-invalid or control bytes into `req.Header.Set("Gitsync-Hash", hash)` drive Exechook.Do(): running the operator's command with cwd = the worktree path and `GITSYNC_HASH` appended to os.Environ() to a state where the receiver is fed a forged or truncated revision identity, defeating “the hash header is always a validated object id” and causing downstream systems acting on a forged revision?

## Target
- File/function: [pkg/hook/exechook.go](pkg/hook/exechook.go) — `Exechook.Do / envKV`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the hash string carry header-invalid or control bytes into `req.Header.Set("Gitsync-Hash", hash)`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the receiver is fed a forged or truncated revision identity
- Invariant to test: the hash header is always a validated object id
- Expected Immunefi impact: downstream systems acting on a forged revision (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: point the hook at a recorder script and assert it receives exactly one invocation per published hash with a validated hex GITSYNC_HASH
