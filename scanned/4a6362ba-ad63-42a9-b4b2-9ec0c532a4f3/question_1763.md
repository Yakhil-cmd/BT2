# Q1763: runWithStdin — prepublish precheckout under both hooks

## Question
Starting from a deployment using both exec and web hooks, can an attacker who times the push so the pre-publish hook runs against a worktree that is still being configured drive runWithStdin(): argv construction, env handling, output buffering, and cmdForLog()'s quoting for logs to a state where the hook sees a partial tree and its success gates a publish of different content, defeating “the pre-publish hook observes exactly the tree that will be published” and causing unverified content published despite a gating hook?

## Target
- File/function: [pkg/cmd/cmd.go](pkg/cmd/cmd.go) — `runWithStdin / cmdForLog`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Times the push so the pre-publish hook runs against a worktree that is still being configured. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the hook sees a partial tree and its success gates a publish of different content
- Invariant to test: the pre-publish hook observes exactly the tree that will be published
- Expected Immunefi impact: unverified content published despite a gating hook (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
