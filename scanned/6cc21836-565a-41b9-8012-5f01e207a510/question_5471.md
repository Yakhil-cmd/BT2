# Q5471: runWithStdin — output buffer growth under shared volume

## Question
Does runWithStdin(): argv construction, env handling, output buffering, and cmdForLog()'s quoting for logs stay safe when an attacker makes a git command emit gigabytes of stdout/stderr (huge fetch verbosity, ref listings) in a shared volume where hook output lands next to consumer data — or can the unbounded bytes.Buffer in runWithStdin() grows until the sidecar is OOM-killed, violating “subprocess output capture is bounded” and producing OOM kill: denial of updates?

## Target
- File/function: [pkg/cmd/cmd.go](pkg/cmd/cmd.go) — `runWithStdin / cmdForLog`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes a git command emit gigabytes of stdout/stderr (huge fetch verbosity, ref listings). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the unbounded bytes.Buffer in runWithStdin() grows until the sidecar is OOM-killed
- Invariant to test: subprocess output capture is bounded
- Expected Immunefi impact: OOM kill: denial of updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
