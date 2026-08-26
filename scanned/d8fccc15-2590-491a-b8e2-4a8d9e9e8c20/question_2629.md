# Q2629: repoSync.fetch — unshallow flip flop under depth1

## Question
Under a deployment using `--depth=1` (the documented shallow default for large repos), an attacker pushes a history that alternately satisfies and violates the --depth boundary (e.g. grafted/shallow-unfriendly merges). In the argv assembled in fetch() (`fetch <repo> <ref> --verbose --no-progress --prune --no-auto-gc` plus --depth/--unshallow/--filter), can that mean isShallow() and the --unshallow branch of fetch() disagree with the repo's real state, so fetch alternates between shallow and full clones, so that the invariant “the shallow/full decision converges and does not depend on attacker-shaped history” no longer holds and the outcome is unbounded disk and bandwidth consumption on the pod volume?

## Target
- File/function: [main.go](main.go) — `repoSync.fetch`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes a history that alternately satisfies and violates the --depth boundary (e.g. grafted/shallow-unfriendly merges). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: isShallow() and the --unshallow branch of fetch() disagree with the repo's real state, so fetch alternates between shallow and full clones
- Invariant to test: the shallow/full decision converges and does not depend on attacker-shaped history
- Expected Immunefi impact: unbounded disk and bandwidth consumption on the pod volume (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: stand up a local bare repo (file:// or `git daemon`), reproduce the ref/object shape, run git-sync for two periods and diff `readlink <link>` against the ref's real tip
