# Q1376: Exechook.Do — env inherit secrets under webhook

## Question
Does Exechook.Do(): running the operator's command with cwd = the worktree path and `GITSYNC_HASH` appended to os.Environ() stay safe when an attacker authors a hook-adjacent payload in the tree that reads the inherited environment in a deployment using `--webhook-url` — or can `os.Environ()` passes `$GITSYNC_PASSWORD`, GitHub App key material, and `$GIT_SSH_COMMAND` into the hook process running in the tree, violating “hook processes receive only the variables they need” and producing credential disclosure to any code reachable from the hook?

## Target
- File/function: [pkg/hook/exechook.go](pkg/hook/exechook.go) — `Exechook.Do / envKV`
- Entrypoint: attacker push -> hook fired after (or before) publish with the new hash and worktree path
- Attacker controls: Authors a hook-adjacent payload in the tree that reads the inherited environment. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: `os.Environ()` passes `$GITSYNC_PASSWORD`, GitHub App key material, and `$GIT_SSH_COMMAND` into the hook process running in the tree
- Invariant to test: hook processes receive only the variables they need
- Expected Immunefi impact: credential disclosure to any code reachable from the hook (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: point the hook at a recorder script and assert it receives exactly one invocation per published hash with a validated hex GITSYNC_HASH
