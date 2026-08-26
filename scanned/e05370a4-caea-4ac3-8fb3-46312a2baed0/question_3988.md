# Q3988: repoSync.initRepo — short hash ambiguity under nodepth after depth

## Question
Under a deployment where --depth was previously set and is now 0, so the --unshallow path is live, an attacker pushes objects engineered to share a short-hash prefix with the pinned revision. In the repo bootstrap in initRepo() (`git init -b git-sync`, `remote get-url/add/set-url origin`), can that mean any abbreviated-hash handling in rev-parse output or worktree naming resolves to the attacker's object, so that the invariant “object identity is always resolved at full length” no longer holds and the outcome is unauthorized content published to consumers?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes objects engineered to share a short-hash prefix with the pinned revision. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: any abbreviated-hash handling in rev-parse output or worktree naming resolves to the attacker's object
- Invariant to test: object identity is always resolved at full length
- Expected Immunefi impact: unauthorized content published to consumers (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
