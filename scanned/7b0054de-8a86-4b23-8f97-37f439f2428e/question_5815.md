# Q5815: repoSync.isShallow — submodule only change under crash resume

## Question
Starting from a resume after the previous process died between fetch and publish, leaving partial state in --root, can an attacker who changes only the submodule gitlink of the tracked branch, keeping the superproject hash strategy stable across syncs drive the shallowness probe isShallow() and its `--unshallow` decision to a state where change detection based on the superproject hash misses or mis-times the update, so publish and hooks fire against content that is not yet materialised, defeating “publish happens only after all content, including submodules, is materialised” and causing consumers read a partially populated tree?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Changes only the submodule gitlink of the tracked branch, keeping the superproject hash strategy stable across syncs. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: change detection based on the superproject hash misses or mis-times the update, so publish and hooks fire against content that is not yet materialised
- Invariant to test: publish happens only after all content, including submodules, is materialised
- Expected Immunefi impact: consumers read a partially populated tree (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: stand up a local bare repo (file:// or `git daemon`), reproduce the ref/object shape, run git-sync for two periods and diff `readlink <link>` against the ref's real tip
