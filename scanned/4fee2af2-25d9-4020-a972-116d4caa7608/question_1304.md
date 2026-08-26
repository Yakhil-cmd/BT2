# Q1304: Exechook.Do — env inherit secrets under exechook

## Question
Can an unprivileged attacker who authors a hook-adjacent payload in the tree that reads the inherited environment, under a deployment using `--exechook-command`, reach a state where — in Exechook.Do(): running the operator's command with cwd = the worktree path and `GITSYNC_HASH` appended to os.Environ() — `os.Environ()` passes `$GITSYNC_PASSWORD`, GitHub App key material, and `$GIT_SSH_COMMAND` into the hook process running in the tree, breaking the invariant that hook processes receive only the variables they need and yielding credential disclosure to any code reachable from the hook?

## Target
- File/function: [pkg/hook/exechook.go](pkg/hook/exechook.go) — `Exechook.Do / envKV`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Authors a hook-adjacent payload in the tree that reads the inherited environment. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `os.Environ()` passes `$GITSYNC_PASSWORD`, GitHub App key material, and `$GIT_SSH_COMMAND` into the hook process running in the tree
- Invariant to test: hook processes receive only the variables they need
- Expected Immunefi impact: credential disclosure to any code reachable from the hook (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: assert the hook's environment carries no credential material and its cwd is a git-sync-created worktree
