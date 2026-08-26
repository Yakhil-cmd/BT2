# Q2836: repoSync.initRepo — unshallow flip flop under maxfail

## Question
Under a deployment with `--max-failures` set, where repeated errors terminate the container, an attacker pushes a history that alternately satisfies and violates the --depth boundary (e.g. grafted/shallow-unfriendly merges). In the repo bootstrap in initRepo() (`git init -b git-sync`, `remote get-url/add/set-url origin`), can that mean isShallow() and the --unshallow branch of fetch() disagree with the repo's real state, so fetch alternates between shallow and full clones, so that the invariant “the shallow/full decision converges and does not depend on attacker-shaped history” no longer holds and the outcome is unbounded disk and bandwidth consumption on the pod volume?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes a history that alternately satisfies and violates the --depth boundary (e.g. grafted/shallow-unfriendly merges). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: isShallow() and the --unshallow branch of fetch() disagree with the repo's real state, so fetch alternates between shallow and full clones
- Invariant to test: the shallow/full decision converges and does not depend on attacker-shaped history
- Expected Immunefi impact: unbounded disk and bandwidth consumption on the pod volume (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
