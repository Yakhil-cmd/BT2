# Q5149: repoSync.fetch — prune driven object loss under crash resume

## Question
Starting from a resume after the previous process died between fetch and publish, leaving partial state in --root, can an attacker who deletes and recreates refs so `--prune` on each fetch drops objects the current worktree still needs drive the argv assembled in fetch() (`fetch <repo> <ref> --verbose --no-progress --prune --no-auto-gc` plus --depth/--unshallow/--filter) to a state where the local repo loses reachability for the published hash, so sanity checks fail and the current worktree is nuked mid-service, defeating “objects backing the currently published worktree are never pruned out from under it” and causing published data disappears from the volume while the symlink still points at it?

## Target
- File/function: [main.go](main.go) — `repoSync.fetch`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Deletes and recreates refs so `--prune` on each fetch drops objects the current worktree still needs. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the local repo loses reachability for the published hash, so sanity checks fail and the current worktree is nuked mid-service
- Invariant to test: objects backing the currently published worktree are never pruned out from under it
- Expected Immunefi impact: published data disappears from the volume while the symlink still points at it (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
