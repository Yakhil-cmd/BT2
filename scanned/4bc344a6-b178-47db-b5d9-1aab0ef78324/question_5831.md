# Q5831: runWithStdin — ctx kill orphans under error file

## Question
Can an unprivileged attacker who keeps a hook or git child alive past the context deadline (child that ignores SIGKILL of its parent group), under `--error-file` enabled inside --root, reach a state where — in runWithStdin(): argv construction, env handling, output buffering, and cmdForLog()'s quoting for logs — CommandContext kills only the direct child, leaving orphans that hold the volume and CPU, breaking the invariant that no subprocess outlives its context and yielding resource exhaustion and locked repository state?

## Target
- File/function: [pkg/cmd/cmd.go](pkg/cmd/cmd.go) — `runWithStdin / cmdForLog`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Keeps a hook or git child alive past the context deadline (child that ignores SIGKILL of its parent group). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: CommandContext kills only the direct child, leaving orphans that hold the volume and CPU
- Invariant to test: no subprocess outlives its context
- Expected Immunefi impact: resource exhaustion and locked repository state (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
