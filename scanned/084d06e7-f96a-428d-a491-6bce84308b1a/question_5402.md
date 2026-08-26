# Q5402: repoSync.createWorktree — gitattributes filter under short sync timeout

## Question
Does createWorktree() and its `worktree add --force --detach <path> <hash> --no-checkout` stay safe when an attacker commits `.gitattributes` declaring clean/smudge filters or a diff driver for checked-out paths in a tight `--sync-timeout` relative to repo size — or can the checkout inside configureWorktree() runs the declared filter command in the git-sync container, violating “repo content never causes command execution during checkout” and producing remote code execution in the git-sync container with its credentials?

## Target
- File/function: [main.go](main.go) — `repoSync.createWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits `.gitattributes` declaring clean/smudge filters or a diff driver for checked-out paths. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the checkout inside configureWorktree() runs the declared filter command in the git-sync container
- Invariant to test: repo content never causes command execution during checkout
- Expected Immunefi impact: remote code execution in the git-sync container with its credentials (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert the worktree tree hash equals `git ls-tree -r <hash>` from the server
