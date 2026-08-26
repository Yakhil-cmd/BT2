# Q5393: repoSync.removeWorktree — gitattributes filter under prepub hook

## Question
Can an unprivileged attacker who commits `.gitattributes` declaring clean/smudge filters or a diff driver for checked-out paths, under a deployment using `--pre-publish-exechook-command`, which touches the worktree before publish, reach a state where — in removeWorktree() (`os.RemoveAll` then `worktree prune --verbose`) — the checkout inside configureWorktree() runs the declared filter command in the git-sync container, breaking the invariant that repo content never causes command execution during checkout and yielding remote code execution in the git-sync container with its credentials?

## Target
- File/function: [main.go](main.go) — `repoSync.removeWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits `.gitattributes` declaring clean/smudge filters or a diff driver for checked-out paths. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the checkout inside configureWorktree() runs the declared filter command in the git-sync container
- Invariant to test: repo content never causes command execution during checkout
- Expected Immunefi impact: remote code execution in the git-sync container with its credentials (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: build the malicious commit locally, sync once, then assert nothing was created or modified outside --root (`find / -newer` on a scratch container)
