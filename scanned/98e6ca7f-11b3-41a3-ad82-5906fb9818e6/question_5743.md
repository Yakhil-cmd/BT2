# Q5743: repoSync.isShallow — submodule only change under maxfail

## Question
Under a deployment with `--max-failures` set, where repeated errors terminate the container, an attacker changes only the submodule gitlink of the tracked branch, keeping the superproject hash strategy stable across syncs. In the shallowness probe isShallow() and its `--unshallow` decision, can that mean change detection based on the superproject hash misses or mis-times the update, so publish and hooks fire against content that is not yet materialised, so that the invariant “publish happens only after all content, including submodules, is materialised” no longer holds and the outcome is consumers read a partially populated tree?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Changes only the submodule gitlink of the tracked branch, keeping the superproject hash strategy stable across syncs. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: change detection based on the superproject hash misses or mis-times the update, so publish and hooks fire against content that is not yet materialised
- Invariant to test: publish happens only after all content, including submodules, is materialised
- Expected Immunefi impact: consumers read a partially populated tree (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
