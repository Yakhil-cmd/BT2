# Q5419: repoSync.isShallow — packfile resource bomb under maxfail

## Question
Can an unprivileged attacker who pushes a pack whose delta chains and object count explode on the client (deep delta, many tiny objects), under a deployment with `--max-failures` set, where repeated errors terminate the container, reach a state where — in the shallowness probe isShallow() and its `--unshallow` decision — fetch consumes CPU and memory beyond --sync-timeout, and the timeout kill leaves partial state behind, breaking the invariant that fetch cost is bounded and a timeout leaves the repo in a recoverable state and yielding sidecar resource exhaustion plus repo corruption requiring a full wipe?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes a pack whose delta chains and object count explode on the client (deep delta, many tiny objects). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: fetch consumes CPU and memory beyond --sync-timeout, and the timeout kill leaves partial state behind
- Invariant to test: fetch cost is bounded and a timeout leaves the repo in a recoverable state
- Expected Immunefi impact: sidecar resource exhaustion plus repo corruption requiring a full wipe (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: stand up a local bare repo (file:// or `git daemon`), reproduce the ref/object shape, run git-sync for two periods and diff `readlink <link>` against the ref's real tip
