# Q5759: runWithStdin — ctx kill orphans under short period

## Question
Does runWithStdin(): argv construction, env handling, output buffering, and cmdForLog()'s quoting for logs stay safe when an attacker keeps a hook or git child alive past the context deadline (child that ignores SIGKILL of its parent group) in a `--period` shorter than the hook's runtime — or can CommandContext kills only the direct child, leaving orphans that hold the volume and CPU, violating “no subprocess outlives its context” and producing resource exhaustion and locked repository state?

## Target
- File/function: [pkg/cmd/cmd.go](pkg/cmd/cmd.go) — `runWithStdin / cmdForLog`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Keeps a hook or git child alive past the context deadline (child that ignores SIGKILL of its parent group). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: CommandContext kills only the direct child, leaving orphans that hold the volume and CPU
- Invariant to test: no subprocess outlives its context
- Expected Immunefi impact: resource exhaustion and locked repository state (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
