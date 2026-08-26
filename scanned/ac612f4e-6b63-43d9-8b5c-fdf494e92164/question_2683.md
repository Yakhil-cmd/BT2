# Q2683: repoSync.isShallow — unshallow flip flop under nodepth after depth

## Question
Can an unprivileged attacker who pushes a history that alternately satisfies and violates the --depth boundary (e.g. grafted/shallow-unfriendly merges), under a deployment where --depth was previously set and is now 0, so the --unshallow path is live, reach a state where — in the shallowness probe isShallow() and its `--unshallow` decision — isShallow() and the --unshallow branch of fetch() disagree with the repo's real state, so fetch alternates between shallow and full clones, breaking the invariant that the shallow/full decision converges and does not depend on attacker-shaped history and yielding unbounded disk and bandwidth consumption on the pod volume?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes a history that alternately satisfies and violates the --depth boundary (e.g. grafted/shallow-unfriendly merges). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: isShallow() and the --unshallow branch of fetch() disagree with the repo's real state, so fetch alternates between shallow and full clones
- Invariant to test: the shallow/full decision converges and does not depend on attacker-shaped history
- Expected Immunefi impact: unbounded disk and bandwidth consumption on the pod volume (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: stand up a local bare repo (file:// or `git daemon`), reproduce the ref/object shape, run git-sync for two periods and diff `readlink <link>` against the ref's real tip
