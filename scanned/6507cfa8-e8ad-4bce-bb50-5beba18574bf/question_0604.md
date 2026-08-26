# Q0604: repoSync.initRepo — refname equals hash under filter blob none

## Question
Starting from a deployment using `--filter=blob:none` partial clone, can an attacker who pushes a branch or tag whose name is a 40-hex string equal to the commit hash pinned in --ref drive the repo bootstrap in initRepo() (`git init -b git-sync`, `remote get-url/add/set-url origin`) to a state where the ref name shadows the pinned object id during fetch/rev-parse, so a pinned-hash deployment silently follows attacker-controlled content, defeating “a hash-pinned --ref can only ever resolve to that exact object id” and causing unauthorized content published while the pin appears intact?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes a branch or tag whose name is a 40-hex string equal to the commit hash pinned in --ref. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the ref name shadows the pinned object id during fetch/rev-parse, so a pinned-hash deployment silently follows attacker-controlled content
- Invariant to test: a hash-pinned --ref can only ever resolve to that exact object id
- Expected Immunefi impact: unauthorized content published while the pin appears intact (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
