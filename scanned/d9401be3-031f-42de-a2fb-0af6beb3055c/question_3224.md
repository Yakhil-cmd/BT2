# Q3224: repoSync.sanityCheckWorktree — duplicate tree entries under crash resume

## Question
Starting from a resume after the previous process died inside configureWorktree(), can an attacker who commits a tree with duplicate or out-of-order entries so different git versions materialise different files drive sanityCheckWorktree() (`dirIsEmpty`, `rev-parse HEAD`, `fsck --connectivity-only`) to a state where two nodes running different git builds publish different bytes under the same hash, defeating “the same hash yields byte-identical published content everywhere” and causing content/identity mismatch across replicas of the consuming workload?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits a tree with duplicate or out-of-order entries so different git versions materialise different files. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: two nodes running different git builds publish different bytes under the same hash
- Invariant to test: the same hash yields byte-identical published content everywhere
- Expected Immunefi impact: content/identity mismatch across replicas of the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: sync once and assert the worktree tree hash equals `git ls-tree -r <hash>` from the server
