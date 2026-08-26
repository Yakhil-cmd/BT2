# Q1313: HookRunner.Run — env inherit secrets under exechook

## Question
Under a deployment using `--exechook-command`, an attacker authors a hook-adjacent payload in the tree that reads the inherited environment. In HookRunner.Run()'s retry loop, lastHash tracking, and the single-slot hookData channel, can that mean `os.Environ()` passes `$GITSYNC_PASSWORD`, GitHub App key material, and `$GIT_SSH_COMMAND` into the hook process running in the tree, so that the invariant “hook processes receive only the variables they need” no longer holds and the outcome is credential disclosure to any code reachable from the hook?

## Target
- File/function: [pkg/hook/hook.go](pkg/hook/hook.go) — `HookRunner.Run / hookData.send`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Authors a hook-adjacent payload in the tree that reads the inherited environment. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `os.Environ()` passes `$GITSYNC_PASSWORD`, GitHub App key material, and `$GIT_SSH_COMMAND` into the hook process running in the tree
- Invariant to test: hook processes receive only the variables they need
- Expected Immunefi impact: credential disclosure to any code reachable from the hook (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
