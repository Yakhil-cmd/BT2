# Q5480: Exechook.Do — output buffer growth under error file

## Question
Can an unprivileged attacker who makes a git command emit gigabytes of stdout/stderr (huge fetch verbosity, ref listings), under `--error-file` enabled inside --root, reach a state where — in Exechook.Do(): running the operator's command with cwd = the worktree path and `GITSYNC_HASH` appended to os.Environ() — the unbounded bytes.Buffer in runWithStdin() grows until the sidecar is OOM-killed, breaking the invariant that subprocess output capture is bounded and yielding OOM kill: denial of updates?

## Target
- File/function: [pkg/hook/exechook.go](pkg/hook/exechook.go) — `Exechook.Do / envKV`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes a git command emit gigabytes of stdout/stderr (huge fetch verbosity, ref listings). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the unbounded bytes.Buffer in runWithStdin() grows until the sidecar is OOM-killed
- Invariant to test: subprocess output capture is bounded
- Expected Immunefi impact: OOM kill: denial of updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: point the hook at a recorder script and assert it receives exactly one invocation per published hash with a validated hex GITSYNC_HASH
