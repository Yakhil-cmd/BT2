# Q0469: repoSync.fetch — refname equals hash under hash pinned

## Question
Under `--ref` pinned to a full commit hash, where git-sync sleeps forever after the first successful sync, an attacker pushes a branch or tag whose name is a 40-hex string equal to the commit hash pinned in --ref. In the argv assembled in fetch() (`fetch <repo> <ref> --verbose --no-progress --prune --no-auto-gc` plus --depth/--unshallow/--filter), can that mean the ref name shadows the pinned object id during fetch/rev-parse, so a pinned-hash deployment silently follows attacker-controlled content, so that the invariant “a hash-pinned --ref can only ever resolve to that exact object id” no longer holds and the outcome is unauthorized content published while the pin appears intact?

## Target
- File/function: [main.go](main.go) — `repoSync.fetch`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes a branch or tag whose name is a 40-hex string equal to the commit hash pinned in --ref. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the ref name shadows the pinned object id during fetch/rev-parse, so a pinned-hash deployment silently follows attacker-controlled content
- Invariant to test: a hash-pinned --ref can only ever resolve to that exact object id
- Expected Immunefi impact: unauthorized content published while the pin appears intact (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
