# Q5554: repoSync.SyncRepo — submodule only change under depth1

## Question
Starting from a deployment using `--depth=1` (the documented shallow default for large repos), can an attacker who changes only the submodule gitlink of the tracked branch, keeping the superproject hash strategy stable across syncs drive the hash resolution and change-detection logic in SyncRepo() (`rev-parse FETCH_HEAD^{}`, currentHash vs remoteHash, `reset --soft`) to a state where change detection based on the superproject hash misses or mis-times the update, so publish and hooks fire against content that is not yet materialised, defeating “publish happens only after all content, including submodules, is materialised” and causing consumers read a partially populated tree?

## Target
- File/function: [main.go](main.go) — `repoSync.SyncRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Changes only the submodule gitlink of the tracked branch, keeping the superproject hash strategy stable across syncs. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: change detection based on the superproject hash misses or mis-times the update, so publish and hooks fire against content that is not yet materialised
- Invariant to test: publish happens only after all content, including submodules, is materialised
- Expected Immunefi impact: consumers read a partially populated tree (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
