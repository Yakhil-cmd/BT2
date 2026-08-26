# Q3239: runWithStdin — onetime exit race under error file

## Question
Can an unprivileged attacker who makes the hook succeed for a stale hash in `--one-time` mode, under `--error-file` enabled inside --root, reach a state where — in runWithStdin(): argv construction, env handling, output buffering, and cmdForLog()'s quoting for logs — sendOneTimeResultAndTerminate() reports success and the process exits 0 while the published tree is not the validated one, breaking the invariant that the one-time exit status reflects the published revision and yielding CI/init-container proceeding on unvalidated content?

## Target
- File/function: [pkg/cmd/cmd.go](pkg/cmd/cmd.go) — `runWithStdin / cmdForLog`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the hook succeed for a stale hash in `--one-time` mode. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: sendOneTimeResultAndTerminate() reports success and the process exits 0 while the published tree is not the validated one
- Invariant to test: the one-time exit status reflects the published revision
- Expected Immunefi impact: CI/init-container proceeding on unvalidated content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
