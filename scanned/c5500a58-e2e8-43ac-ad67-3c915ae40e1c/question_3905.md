# Q3905: HookRunner.Run — webhook header forge under exechook

## Question
Under a deployment using `--exechook-command`, an attacker makes the hash string carry header-invalid or control bytes into `req.Header.Set("Gitsync-Hash", hash)`. In HookRunner.Run()'s retry loop, lastHash tracking, and the single-slot hookData channel, can that mean the receiver is fed a forged or truncated revision identity, so that the invariant “the hash header is always a validated object id” no longer holds and the outcome is downstream systems acting on a forged revision?

## Target
- File/function: [pkg/hook/hook.go](pkg/hook/hook.go) — `HookRunner.Run / hookData.send`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the hash string carry header-invalid or control bytes into `req.Header.Set("Gitsync-Hash", hash)`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the receiver is fed a forged or truncated revision identity
- Invariant to test: the hash header is always a validated object id
- Expected Immunefi impact: downstream systems acting on a forged revision (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
