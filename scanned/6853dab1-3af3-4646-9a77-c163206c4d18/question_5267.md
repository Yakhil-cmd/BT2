# Q5267: repoSync.configureWorktree — gitattributes filter under group write

## Question
Starting from a deployment using `--group-write`, where the umask is 0002 and the volume is shared with a non-root consumer, can an attacker who commits `.gitattributes` declaring clean/smudge filters or a diff driver for checked-out paths drive configureWorktree(): the relative `.git` file rewrite, sparse-checkout wiring, `reset --hard <hash> --`, and submodule update to a state where the checkout inside configureWorktree() runs the declared filter command in the git-sync container, defeating “repo content never causes command execution during checkout” and causing remote code execution in the git-sync container with its credentials?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits `.gitattributes` declaring clean/smudge filters or a diff driver for checked-out paths. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the checkout inside configureWorktree() runs the declared filter command in the git-sync container
- Invariant to test: repo content never causes command execution during checkout
- Expected Immunefi impact: remote code execution in the git-sync container with its credentials (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert the worktree tree hash equals `git ls-tree -r <hash>` from the server
