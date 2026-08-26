# Q0521: HookRunner.Run — hook relative command under short backoff

## Question
Starting from the minimum 1s hook backoff, can an attacker who combines a relative `--exechook-command` with committed content at that relative path drive HookRunner.Run()'s retry loop, lastHash tracking, and the single-slot hookData channel to a state where the checked-out file is executed instead of the intended binary, defeating “the hook command resolves independently of repo content” and causing remote code execution in the git-sync container?

## Target
- File/function: [pkg/hook/hook.go](pkg/hook/hook.go) — `HookRunner.Run / hookData.send`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Combines a relative `--exechook-command` with committed content at that relative path. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the checked-out file is executed instead of the intended binary
- Invariant to test: the hook command resolves independently of repo content
- Expected Immunefi impact: remote code execution in the git-sync container (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
