# Q1675: repoSync.isShallow — moved tag under depth1

## Question
Can an unprivileged attacker who moves an existing tag (delete + repush) that --ref names, under a deployment using `--depth=1` (the documented shallow default for large repos), reach a state where — in the shallowness probe isShallow() and its `--unshallow` decision — the `--prune`-bearing fetch silently retargets a supposedly immutable tag and republishes different content under the same human-facing ref, breaking the invariant that a tag-pinned deployment is immutable unless the tag legitimately moves and the change is detected and yielding unauthorized content published under a pinned tag?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Moves an existing tag (delete + repush) that --ref names. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the `--prune`-bearing fetch silently retargets a supposedly immutable tag and republishes different content under the same human-facing ref
- Invariant to test: a tag-pinned deployment is immutable unless the tag legitimately moves and the change is detected
- Expected Immunefi impact: unauthorized content published under a pinned tag (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
