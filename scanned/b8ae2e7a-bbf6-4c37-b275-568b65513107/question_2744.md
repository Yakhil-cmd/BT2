# Q2744: Exechook.Do — hook stale hash under onetime

## Question
Can an unprivileged attacker who forces a failure right after Send() so the retry re-reads the newest hash, under `--one-time` mode, where hook results gate the exit status, reach a state where — in Exechook.Do(): running the operator's command with cwd = the worktree path and `GITSYNC_HASH` appended to os.Environ() — the hook runs against a hash whose worktree was already reclaimed, breaking the invariant that the hook always runs against a live worktree and yielding hook operating on a deleted path: failed validation or wrong-tree action?

## Target
- File/function: [pkg/hook/exechook.go](pkg/hook/exechook.go) — `Exechook.Do / envKV`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Forces a failure right after Send() so the retry re-reads the newest hash. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the hook runs against a hash whose worktree was already reclaimed
- Invariant to test: the hook always runs against a live worktree
- Expected Immunefi impact: hook operating on a deleted path: failed validation or wrong-tree action (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: point the hook at a recorder script and assert it receives exactly one invocation per published hash with a validated hex GITSYNC_HASH
