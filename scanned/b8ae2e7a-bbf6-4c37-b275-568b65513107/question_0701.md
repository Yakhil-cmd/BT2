# Q0701: HookRunner.Run — hash env injection under prepub hook

## Question
Can an unprivileged attacker who makes the resolved hash string carry non-hex characters (non-commit peel result, forged worktree leaf), under a deployment using `--pre-publish-exechook-command`, reach a state where — in HookRunner.Run()'s retry loop, lastHash tracking, and the single-slot hookData channel — `GITSYNC_HASH` carries attacker bytes into a shell-based hook's environment, breaking the invariant that GITSYNC_HASH is always a validated object id and yielding command injection inside the operator's hook script?

## Target
- File/function: [pkg/hook/hook.go](pkg/hook/hook.go) — `HookRunner.Run / hookData.send`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Makes the resolved hash string carry non-hex characters (non-commit peel result, forged worktree leaf). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `GITSYNC_HASH` carries attacker bytes into a shell-based hook's environment
- Invariant to test: GITSYNC_HASH is always a validated object id
- Expected Immunefi impact: command injection inside the operator's hook script (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
