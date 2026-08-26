# Q3095: runWithStdin — onetime exit race under onetime

## Question
Can an unprivileged attacker who makes the hook succeed for a stale hash in `--one-time` mode, under `--one-time` mode, where hook results gate the exit status, reach a state where — in runWithStdin(): argv construction, env handling, output buffering, and cmdForLog()'s quoting for logs — sendOneTimeResultAndTerminate() reports success and the process exits 0 while the published tree is not the validated one, breaking the invariant that the one-time exit status reflects the published revision and yielding CI/init-container proceeding on unvalidated content?

## Target
- File/function: [pkg/cmd/cmd.go](pkg/cmd/cmd.go) — `runWithStdin / cmdForLog`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the hook succeed for a stale hash in `--one-time` mode. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: sendOneTimeResultAndTerminate() reports success and the process exits 0 while the published tree is not the validated one
- Invariant to test: the one-time exit status reflects the published revision
- Expected Immunefi impact: CI/init-container proceeding on unvalidated content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
