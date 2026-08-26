# Q3188: repoSync.sanityCheckWorktree — duplicate tree entries under submodules recursive

## Question
Does sanityCheckWorktree() (`dirIsEmpty`, `rev-parse HEAD`, `fsck --connectivity-only`) stay safe when an attacker commits a tree with duplicate or out-of-order entries so different git versions materialise different files in the default `--submodules=recursive` setting — or can two nodes running different git builds publish different bytes under the same hash, violating “the same hash yields byte-identical published content everywhere” and producing content/identity mismatch across replicas of the consuming workload?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckWorktree`
- Entrypoint: attacker push to the synced repo -> `worktree add` + `reset --hard` during the sync loop
- Attacker controls: Commits a tree with duplicate or out-of-order entries so different git versions materialise different files. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: two nodes running different git builds publish different bytes under the same hash
- Invariant to test: the same hash yields byte-identical published content everywhere
- Expected Immunefi impact: content/identity mismatch across replicas of the consuming workload (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: build the malicious commit locally, sync once, then assert nothing was created or modified outside --root (`find / -newer` on a scratch container)
