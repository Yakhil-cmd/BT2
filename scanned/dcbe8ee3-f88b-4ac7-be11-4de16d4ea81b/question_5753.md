# Q5753: repoSync.removeWorktree — lfs pointer fetch under short sync timeout

## Question
Does removeWorktree() (`os.RemoveAll` then `worktree prune --verbose`) stay safe when an attacker commits LFS pointer files and `.gitattributes` binding them to the lfs filter in a tight `--sync-timeout` relative to repo size — or can checkout triggers outbound requests to an attacker-named LFS endpoint carrying git-sync's credentials, violating “checkout performs no network I/O to attacker-named hosts” and producing credential disclosure to an attacker-controlled endpoint?

## Target
- File/function: [main.go](main.go) — `repoSync.removeWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits LFS pointer files and `.gitattributes` binding them to the lfs filter. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: checkout triggers outbound requests to an attacker-named LFS endpoint carrying git-sync's credentials
- Invariant to test: checkout performs no network I/O to attacker-named hosts
- Expected Immunefi impact: credential disclosure to an attacker-controlled endpoint (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once with the fixture and assert no subprocess other than the configured `--git` binary was executed (strace/`GIT_TRACE=1`)
