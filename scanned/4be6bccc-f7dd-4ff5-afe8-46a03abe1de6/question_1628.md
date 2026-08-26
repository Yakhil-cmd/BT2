# Q1628: Exechook.Do — prepublish precheckout under exechook

## Question
Under a deployment using `--exechook-command`, an attacker times the push so the pre-publish hook runs against a worktree that is still being configured. In Exechook.Do(): running the operator's command with cwd = the worktree path and `GITSYNC_HASH` appended to os.Environ(), can that mean the hook sees a partial tree and its success gates a publish of different content, so that the invariant “the pre-publish hook observes exactly the tree that will be published” no longer holds and the outcome is unverified content published despite a gating hook?

## Target
- File/function: [pkg/hook/exechook.go](pkg/hook/exechook.go) — `Exechook.Do / envKV`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Times the push so the pre-publish hook runs against a worktree that is still being configured. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the hook sees a partial tree and its success gates a publish of different content
- Invariant to test: the pre-publish hook observes exactly the tree that will be published
- Expected Immunefi impact: unverified content published despite a gating hook (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
