# Q5453: HookRunner.Run — output buffer growth under shared volume

## Question
Can an unprivileged attacker who makes a git command emit gigabytes of stdout/stderr (huge fetch verbosity, ref listings), under a shared volume where hook output lands next to consumer data, reach a state where — in HookRunner.Run()'s retry loop, lastHash tracking, and the single-slot hookData channel — the unbounded bytes.Buffer in runWithStdin() grows until the sidecar is OOM-killed, breaking the invariant that subprocess output capture is bounded and yielding OOM kill: denial of updates?

## Target
- File/function: [pkg/hook/hook.go](pkg/hook/hook.go) — `HookRunner.Run / hookData.send`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes a git command emit gigabytes of stdout/stderr (huge fetch verbosity, ref listings). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the unbounded bytes.Buffer in runWithStdin() grows until the sidecar is OOM-killed
- Invariant to test: subprocess output capture is bounded
- Expected Immunefi impact: OOM kill: denial of updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: point the hook at a recorder script and assert it receives exactly one invocation per published hash with a validated hex GITSYNC_HASH
