# Q1889: HookRunner.Run — prepublish precheckout under shared volume

## Question
Under a shared volume where hook output lands next to consumer data, an attacker times the push so the pre-publish hook runs against a worktree that is still being configured. In HookRunner.Run()'s retry loop, lastHash tracking, and the single-slot hookData channel, can that mean the hook sees a partial tree and its success gates a publish of different content, so that the invariant “the pre-publish hook observes exactly the tree that will be published” no longer holds and the outcome is unverified content published despite a gating hook?

## Target
- File/function: [pkg/hook/hook.go](pkg/hook/hook.go) — `HookRunner.Run / hookData.send`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Times the push so the pre-publish hook runs against a worktree that is still being configured. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the hook sees a partial tree and its success gates a publish of different content
- Invariant to test: the pre-publish hook observes exactly the tree that will be published
- Expected Immunefi impact: unverified content published despite a gating hook (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
