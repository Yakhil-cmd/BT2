# Q2132: Exechook.Do — hook retry storm under short backoff

## Question
Starting from the minimum 1s hook backoff, can an attacker who makes the hook fail deterministically (content the hook rejects) drive Exechook.Do(): running the operator's command with cwd = the worktree path and `GITSYNC_HASH` appended to os.Environ() to a state where HookRunner.Run() retries forever at --exechook-backoff while the sync loop keeps publishing, defeating “hook failure is bounded and surfaced” and causing resource exhaustion plus silent divergence between published and hook-validated state?

## Target
- File/function: [pkg/hook/exechook.go](pkg/hook/exechook.go) — `Exechook.Do / envKV`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the hook fail deterministically (content the hook rejects). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: HookRunner.Run() retries forever at --exechook-backoff while the sync loop keeps publishing
- Invariant to test: hook failure is bounded and surfaced
- Expected Immunefi impact: resource exhaustion plus silent divergence between published and hook-validated state (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
