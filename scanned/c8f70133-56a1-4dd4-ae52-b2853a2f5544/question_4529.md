# Q4529: repoSync.removeWorktree — undeletable content under crash resume

## Question
Can an unprivileged attacker who commits a deep path tree that exceeds PATH_MAX on materialisation or removal, under a resume after the previous process died inside configureWorktree(), reach a state where — in removeWorktree() (`os.RemoveAll` then `worktree prune --verbose`) — checkout partially succeeds and RemoveAll later fails, accumulating undeletable worktrees, breaking the invariant that any tree that can be checked out can also be cleaned up and yielding volume exhaustion and permanent sync failure?

## Target
- File/function: [main.go](main.go) — `repoSync.removeWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits a deep path tree that exceeds PATH_MAX on materialisation or removal. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: checkout partially succeeds and RemoveAll later fails, accumulating undeletable worktrees
- Invariant to test: any tree that can be checked out can also be cleaned up
- Expected Immunefi impact: volume exhaustion and permanent sync failure (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: build the malicious commit locally, sync once, then assert nothing was created or modified outside --root (`find / -newer` on a scratch container)
