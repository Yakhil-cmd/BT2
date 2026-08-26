# Q5437: repoSync.fetch — packfile resource bomb under filter blob none

## Question
Starting from a deployment using `--filter=blob:none` partial clone, can an attacker who pushes a pack whose delta chains and object count explode on the client (deep delta, many tiny objects) drive the argv assembled in fetch() (`fetch <repo> <ref> --verbose --no-progress --prune --no-auto-gc` plus --depth/--unshallow/--filter) to a state where fetch consumes CPU and memory beyond --sync-timeout, and the timeout kill leaves partial state behind, defeating “fetch cost is bounded and a timeout leaves the repo in a recoverable state” and causing sidecar resource exhaustion plus repo corruption requiring a full wipe?

## Target
- File/function: [main.go](main.go) — `repoSync.fetch`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes a pack whose delta chains and object count explode on the client (deep delta, many tiny objects). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: fetch consumes CPU and memory beyond --sync-timeout, and the timeout kill leaves partial state behind
- Invariant to test: fetch cost is bounded and a timeout leaves the repo in a recoverable state
- Expected Immunefi impact: sidecar resource exhaustion plus repo corruption requiring a full wipe (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
