# Q1927: repoSync.isShallow — moved tag under crash resume

## Question
Starting from a resume after the previous process died between fetch and publish, leaving partial state in --root, can an attacker who moves an existing tag (delete + repush) that --ref names drive the shallowness probe isShallow() and its `--unshallow` decision to a state where the `--prune`-bearing fetch silently retargets a supposedly immutable tag and republishes different content under the same human-facing ref, defeating “a tag-pinned deployment is immutable unless the tag legitimately moves and the change is detected” and causing unauthorized content published under a pinned tag?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Moves an existing tag (delete + repush) that --ref names. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the `--prune`-bearing fetch silently retargets a supposedly immutable tag and republishes different content under the same human-facing ref
- Invariant to test: a tag-pinned deployment is immutable unless the tag legitimately moves and the change is detected
- Expected Immunefi impact: unauthorized content published under a pinned tag (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: stand up a local bare repo (file:// or `git daemon`), reproduce the ref/object shape, run git-sync for two periods and diff `readlink <link>` against the ref's real tip
