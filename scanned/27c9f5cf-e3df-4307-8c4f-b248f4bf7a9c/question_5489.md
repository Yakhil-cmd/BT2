# Q5489: HookRunner.Run — output buffer growth under error file

## Question
Under `--error-file` enabled inside --root, an attacker makes a git command emit gigabytes of stdout/stderr (huge fetch verbosity, ref listings). In HookRunner.Run()'s retry loop, lastHash tracking, and the single-slot hookData channel, can that mean the unbounded bytes.Buffer in runWithStdin() grows until the sidecar is OOM-killed, so that the invariant “subprocess output capture is bounded” no longer holds and the outcome is OOM kill: denial of updates?

## Target
- File/function: [pkg/hook/hook.go](pkg/hook/hook.go) — `HookRunner.Run / hookData.send`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes a git command emit gigabytes of stdout/stderr (huge fetch verbosity, ref listings). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the unbounded bytes.Buffer in runWithStdin() grows until the sidecar is OOM-killed
- Invariant to test: subprocess output capture is bounded
- Expected Immunefi impact: OOM kill: denial of updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
