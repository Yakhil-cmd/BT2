# Q4303: repoSync.isShallow — empty repo first sync under nodepth after depth

## Question
Under a deployment where --depth was previously set and is now 0, so the --unshallow path is live, an attacker makes the remote ref exist but point at an empty tree on the very first sync. In the shallowness probe isShallow() and its `--unshallow` decision, can that mean initRepo()/sanityCheckRepo() treat the resulting root as invalid and wipe it, or a zero-file worktree is published as ready, so that the invariant “an empty publish is never reported as a successful, ready sync” no longer holds and the outcome is consumers served an empty dataset while readiness reports success?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Makes the remote ref exist but point at an empty tree on the very first sync. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: initRepo()/sanityCheckRepo() treat the resulting root as invalid and wipe it, or a zero-file worktree is published as ready
- Invariant to test: an empty publish is never reported as a successful, ready sync
- Expected Immunefi impact: consumers served an empty dataset while readiness reports success (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
