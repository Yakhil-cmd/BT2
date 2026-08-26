# Q2647: repoSync.isShallow — unshallow flip flop under depth1

## Question
Starting from a deployment using `--depth=1` (the documented shallow default for large repos), can an attacker who pushes a history that alternately satisfies and violates the --depth boundary (e.g. grafted/shallow-unfriendly merges) drive the shallowness probe isShallow() and its `--unshallow` decision to a state where isShallow() and the --unshallow branch of fetch() disagree with the repo's real state, so fetch alternates between shallow and full clones, defeating “the shallow/full decision converges and does not depend on attacker-shaped history” and causing unbounded disk and bandwidth consumption on the pod volume?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes a history that alternately satisfies and violates the --depth boundary (e.g. grafted/shallow-unfriendly merges). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: isShallow() and the --unshallow branch of fetch() disagree with the repo's real state, so fetch alternates between shallow and full clones
- Invariant to test: the shallow/full decision converges and does not depend on attacker-shaped history
- Expected Immunefi impact: unbounded disk and bandwidth consumption on the pod volume (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
