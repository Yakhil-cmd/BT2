# Q3032: Exechook.Do — onetime exit race under both hooks

## Question
Can an unprivileged attacker who makes the hook succeed for a stale hash in `--one-time` mode, under a deployment using both exec and web hooks, reach a state where — in Exechook.Do(): running the operator's command with cwd = the worktree path and `GITSYNC_HASH` appended to os.Environ() — sendOneTimeResultAndTerminate() reports success and the process exits 0 while the published tree is not the validated one, breaking the invariant that the one-time exit status reflects the published revision and yielding CI/init-container proceeding on unvalidated content?

## Target
- File/function: [pkg/hook/exechook.go](pkg/hook/exechook.go) — `Exechook.Do / envKV`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the hook succeed for a stale hash in `--one-time` mode. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: sendOneTimeResultAndTerminate() reports success and the process exits 0 while the published tree is not the validated one
- Invariant to test: the one-time exit status reflects the published revision
- Expected Immunefi impact: CI/init-container proceeding on unvalidated content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: point the hook at a recorder script and assert it receives exactly one invocation per published hash with a validated hex GITSYNC_HASH
