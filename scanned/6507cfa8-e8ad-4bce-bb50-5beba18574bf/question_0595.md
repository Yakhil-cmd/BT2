# Q0595: repoSync.isShallow — refname equals hash under filter blob none

## Question
Does the shallowness probe isShallow() and its `--unshallow` decision stay safe when an attacker pushes a branch or tag whose name is a 40-hex string equal to the commit hash pinned in --ref in a deployment using `--filter=blob:none` partial clone — or can the ref name shadows the pinned object id during fetch/rev-parse, so a pinned-hash deployment silently follows attacker-controlled content, violating “a hash-pinned --ref can only ever resolve to that exact object id” and producing unauthorized content published while the pin appears intact?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes a branch or tag whose name is a 40-hex string equal to the commit hash pinned in --ref. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the ref name shadows the pinned object id during fetch/rev-parse, so a pinned-hash deployment silently follows attacker-controlled content
- Invariant to test: a hash-pinned --ref can only ever resolve to that exact object id
- Expected Immunefi impact: unauthorized content published while the pin appears intact (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
