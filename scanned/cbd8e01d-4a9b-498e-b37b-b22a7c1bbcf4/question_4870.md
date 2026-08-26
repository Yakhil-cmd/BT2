# Q4870: repoSync.SyncRepo — prune driven object loss under first sync

## Question
Can an unprivileged attacker who deletes and recreates refs so `--prune` on each fetch drops objects the current worktree still needs, under the very first sync after container start, when the root is empty and syncCount is 0, reach a state where — in the hash resolution and change-detection logic in SyncRepo() (`rev-parse FETCH_HEAD^{}`, currentHash vs remoteHash, `reset --soft`) — the local repo loses reachability for the published hash, so sanity checks fail and the current worktree is nuked mid-service, breaking the invariant that objects backing the currently published worktree are never pruned out from under it and yielding published data disappears from the volume while the symlink still points at it?

## Target
- File/function: [main.go](main.go) — `repoSync.SyncRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Deletes and recreates refs so `--prune` on each fetch drops objects the current worktree still needs. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the local repo loses reachability for the published hash, so sanity checks fail and the current worktree is nuked mid-service
- Invariant to test: objects backing the currently published worktree are never pruned out from under it
- Expected Immunefi impact: published data disappears from the volume while the symlink still points at it (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
