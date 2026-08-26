# Q1711: repoSync.isShallow — moved tag under nodepth after depth

## Question
Under a deployment where --depth was previously set and is now 0, so the --unshallow path is live, an attacker moves an existing tag (delete + repush) that --ref names. In the shallowness probe isShallow() and its `--unshallow` decision, can that mean the `--prune`-bearing fetch silently retargets a supposedly immutable tag and republishes different content under the same human-facing ref, so that the invariant “a tag-pinned deployment is immutable unless the tag legitimately moves and the change is detected” no longer holds and the outcome is unauthorized content published under a pinned tag?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Moves an existing tag (delete + repush) that --ref names. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the `--prune`-bearing fetch silently retargets a supposedly immutable tag and republishes different content under the same human-facing ref
- Invariant to test: a tag-pinned deployment is immutable unless the tag legitimately moves and the change is detected
- Expected Immunefi impact: unauthorized content published under a pinned tag (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: stand up a local bare repo (file:// or `git daemon`), reproduce the ref/object shape, run git-sync for two periods and diff `readlink <link>` against the ref's real tip
