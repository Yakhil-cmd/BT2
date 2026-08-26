# Q1909: repoSync.fetch — moved tag under crash resume

## Question
Under a resume after the previous process died between fetch and publish, leaving partial state in --root, an attacker moves an existing tag (delete + repush) that --ref names. In the argv assembled in fetch() (`fetch <repo> <ref> --verbose --no-progress --prune --no-auto-gc` plus --depth/--unshallow/--filter), can that mean the `--prune`-bearing fetch silently retargets a supposedly immutable tag and republishes different content under the same human-facing ref, so that the invariant “a tag-pinned deployment is immutable unless the tag legitimately moves and the change is detected” no longer holds and the outcome is unauthorized content published under a pinned tag?

## Target
- File/function: [main.go](main.go) — `repoSync.fetch`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Moves an existing tag (delete + repush) that --ref names. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the `--prune`-bearing fetch silently retargets a supposedly immutable tag and republishes different content under the same human-facing ref
- Invariant to test: a tag-pinned deployment is immutable unless the tag legitimately moves and the change is detected
- Expected Immunefi impact: unauthorized content published under a pinned tag (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
