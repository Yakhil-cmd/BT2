# Q0134: Webhook.Do — hook cwd content under both hooks

## Question
Under a deployment using both exec and web hooks, an attacker commits executables, `.env`-style files, or dotfiles at the root of the published tree. In Webhook.Do(): the `Gitsync-Hash` header, success-status check, and unbounded response-body read, can that mean the exec hook runs with cwd set to that worktree, so relative-path invocations and shell startup files inside it are picked up, so that the invariant “hook execution never resolves programs or config out of the synced tree” no longer holds and the outcome is code execution in the git-sync container with the operator's hook privileges?

## Target
- File/function: [pkg/hook/webhook.go](pkg/hook/webhook.go) — `Webhook.Do`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Commits executables, `.env`-style files, or dotfiles at the root of the published tree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the exec hook runs with cwd set to that worktree, so relative-path invocations and shell startup files inside it are picked up
- Invariant to test: hook execution never resolves programs or config out of the synced tree
- Expected Immunefi impact: code execution in the git-sync container with the operator's hook privileges (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: publish rapidly and assert the hook observed every published revision, or that skipping is explicitly reported
