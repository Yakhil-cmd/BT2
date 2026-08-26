# Q2753: HookRunner.Run — hook stale hash under onetime

## Question
Under `--one-time` mode, where hook results gate the exit status, an attacker forces a failure right after Send() so the retry re-reads the newest hash. In HookRunner.Run()'s retry loop, lastHash tracking, and the single-slot hookData channel, can that mean the hook runs against a hash whose worktree was already reclaimed, so that the invariant “the hook always runs against a live worktree” no longer holds and the outcome is hook operating on a deleted path: failed validation or wrong-tree action?

## Target
- File/function: [pkg/hook/hook.go](pkg/hook/hook.go) — `HookRunner.Run / hookData.send`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Forces a failure right after Send() so the retry re-reads the newest hash. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the hook runs against a hash whose worktree was already reclaimed
- Invariant to test: the hook always runs against a live worktree
- Expected Immunefi impact: hook operating on a deleted path: failed validation or wrong-tree action (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
