# Q2708: Exechook.Do — hook stale hash under both hooks

## Question
Starting from a deployment using both exec and web hooks, can an attacker who forces a failure right after Send() so the retry re-reads the newest hash drive Exechook.Do(): running the operator's command with cwd = the worktree path and `GITSYNC_HASH` appended to os.Environ() to a state where the hook runs against a hash whose worktree was already reclaimed, defeating “the hook always runs against a live worktree” and causing hook operating on a deleted path: failed validation or wrong-tree action?

## Target
- File/function: [pkg/hook/exechook.go](pkg/hook/exechook.go) — `Exechook.Do / envKV`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Forces a failure right after Send() so the retry re-reads the newest hash. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the hook runs against a hash whose worktree was already reclaimed
- Invariant to test: the hook always runs against a live worktree
- Expected Immunefi impact: hook operating on a deleted path: failed validation or wrong-tree action (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
