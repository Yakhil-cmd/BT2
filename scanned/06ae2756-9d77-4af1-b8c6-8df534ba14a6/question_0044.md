# Q0044: Exechook.Do — hook cwd content under prepub hook

## Question
Under a deployment using `--pre-publish-exechook-command`, an attacker commits executables, `.env`-style files, or dotfiles at the root of the published tree. In Exechook.Do(): running the operator's command with cwd = the worktree path and `GITSYNC_HASH` appended to os.Environ(), can that mean the exec hook runs with cwd set to that worktree, so relative-path invocations and shell startup files inside it are picked up, so that the invariant “hook execution never resolves programs or config out of the synced tree” no longer holds and the outcome is code execution in the git-sync container with the operator's hook privileges?

## Target
- File/function: [pkg/hook/exechook.go](pkg/hook/exechook.go) — `Exechook.Do / envKV`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Commits executables, `.env`-style files, or dotfiles at the root of the published tree. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the exec hook runs with cwd set to that worktree, so relative-path invocations and shell startup files inside it are picked up
- Invariant to test: hook execution never resolves programs or config out of the synced tree
- Expected Immunefi impact: code execution in the git-sync container with the operator's hook privileges (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
