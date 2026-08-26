# Q1808: Exechook.Do — prepublish precheckout under short backoff

## Question
Does Exechook.Do(): running the operator's command with cwd = the worktree path and `GITSYNC_HASH` appended to os.Environ() stay safe when an attacker times the push so the pre-publish hook runs against a worktree that is still being configured in the minimum 1s hook backoff — or can the hook sees a partial tree and its success gates a publish of different content, violating “the pre-publish hook observes exactly the tree that will be published” and producing unverified content published despite a gating hook?

## Target
- File/function: [pkg/hook/exechook.go](pkg/hook/exechook.go) — `Exechook.Do / envKV`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Times the push so the pre-publish hook runs against a worktree that is still being configured. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the hook sees a partial tree and its success gates a publish of different content
- Invariant to test: the pre-publish hook observes exactly the tree that will be published
- Expected Immunefi impact: unverified content published despite a gating hook (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
