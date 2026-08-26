# Q5239: repoSync.isShallow — packfile resource bomb under depth1

## Question
Starting from a deployment using `--depth=1` (the documented shallow default for large repos), can an attacker who pushes a pack whose delta chains and object count explode on the client (deep delta, many tiny objects) drive the shallowness probe isShallow() and its `--unshallow` decision to a state where fetch consumes CPU and memory beyond --sync-timeout, and the timeout kill leaves partial state behind, defeating “fetch cost is bounded and a timeout leaves the repo in a recoverable state” and causing sidecar resource exhaustion plus repo corruption requiring a full wipe?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes a pack whose delta chains and object count explode on the client (deep delta, many tiny objects). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: fetch consumes CPU and memory beyond --sync-timeout, and the timeout kill leaves partial state behind
- Invariant to test: fetch cost is bounded and a timeout leaves the repo in a recoverable state
- Expected Immunefi impact: sidecar resource exhaustion plus repo corruption requiring a full wipe (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
