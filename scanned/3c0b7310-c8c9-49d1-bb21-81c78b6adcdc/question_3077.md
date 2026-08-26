# Q3077: HookRunner.Run — onetime exit race under onetime

## Question
Does HookRunner.Run()'s retry loop, lastHash tracking, and the single-slot hookData channel stay safe when an attacker makes the hook succeed for a stale hash in `--one-time` mode in `--one-time` mode, where hook results gate the exit status — or can sendOneTimeResultAndTerminate() reports success and the process exits 0 while the published tree is not the validated one, violating “the one-time exit status reflects the published revision” and producing CI/init-container proceeding on unvalidated content?

## Target
- File/function: [pkg/hook/hook.go](pkg/hook/hook.go) — `HookRunner.Run / hookData.send`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the hook succeed for a stale hash in `--one-time` mode. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: sendOneTimeResultAndTerminate() reports success and the process exits 0 while the published tree is not the validated one
- Invariant to test: the one-time exit status reflects the published revision
- Expected Immunefi impact: CI/init-container proceeding on unvalidated content (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
