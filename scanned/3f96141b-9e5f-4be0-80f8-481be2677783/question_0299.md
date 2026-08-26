# Q0299: repoSync.configureWorktree — checkout symlink escape under crash resume

## Question
Under a resume after the previous process died inside configureWorktree(), an attacker commits a symlink that points outside the worktree and a later path that traverses through it. In configureWorktree(): the relative `.git` file rewrite, sparse-checkout wiring, `reset --hard <hash> --`, and submodule update, can that mean the `reset --hard` checkout writes files through the attacker's symlink to a location outside --root, so that the invariant “no checkout writes resolve outside the worktree directory” no longer holds and the outcome is arbitrary file write in the container or a co-mounted volume, leading to code execution?

## Target
- File/function: [main.go](main.go) — `repoSync.configureWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits a symlink that points outside the worktree and a later path that traverses through it. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the `reset --hard` checkout writes files through the attacker's symlink to a location outside --root
- Invariant to test: no checkout writes resolve outside the worktree directory
- Expected Immunefi impact: arbitrary file write in the container or a co-mounted volume, leading to code execution (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: build the malicious commit locally, sync once, then assert nothing was created or modified outside --root (`find / -newer` on a scratch container)
