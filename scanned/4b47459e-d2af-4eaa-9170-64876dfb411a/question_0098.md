# Q0098: Webhook.Do — hook cwd content under webhook

## Question
Can an unprivileged attacker who commits executables, `.env`-style files, or dotfiles at the root of the published tree, under a deployment using `--webhook-url`, reach a state where — in Webhook.Do(): the `Gitsync-Hash` header, success-status check, and unbounded response-body read — the exec hook runs with cwd set to that worktree, so relative-path invocations and shell startup files inside it are picked up, breaking the invariant that hook execution never resolves programs or config out of the synced tree and yielding code execution in the git-sync container with the operator's hook privileges?

## Target
- File/function: [pkg/hook/webhook.go](pkg/hook/webhook.go) — `Webhook.Do`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Commits executables, `.env`-style files, or dotfiles at the root of the published tree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the exec hook runs with cwd set to that worktree, so relative-path invocations and shell startup files inside it are picked up
- Invariant to test: hook execution never resolves programs or config out of the synced tree
- Expected Immunefi impact: code execution in the git-sync container with the operator's hook privileges (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
