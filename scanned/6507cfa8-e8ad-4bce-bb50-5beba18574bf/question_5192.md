# Q5192: Exechook.Do — output buffer growth under exechook

## Question
Can an unprivileged attacker who makes a git command emit gigabytes of stdout/stderr (huge fetch verbosity, ref listings), under a deployment using `--exechook-command`, reach a state where — in Exechook.Do(): running the operator's command with cwd = the worktree path and `GITSYNC_HASH` appended to os.Environ() — the unbounded bytes.Buffer in runWithStdin() grows until the sidecar is OOM-killed, breaking the invariant that subprocess output capture is bounded and yielding OOM kill: denial of updates?

## Target
- File/function: [pkg/hook/exechook.go](pkg/hook/exechook.go) — `Exechook.Do / envKV`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes a git command emit gigabytes of stdout/stderr (huge fetch verbosity, ref listings). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the unbounded bytes.Buffer in runWithStdin() grows until the sidecar is OOM-killed
- Invariant to test: subprocess output capture is bounded
- Expected Immunefi impact: OOM kill: denial of updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
