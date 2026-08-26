# Q5320: repoSync.initRepo — packfile resource bomb under onetime

## Question
Does the repo bootstrap in initRepo() (`git init -b git-sync`, `remote get-url/add/set-url origin`) stay safe when an attacker pushes a pack whose delta chains and object count explode on the client (deep delta, many tiny objects) in `--one-time` mode, where the process must exit with a status after a single sync — or can fetch consumes CPU and memory beyond --sync-timeout, and the timeout kill leaves partial state behind, violating “fetch cost is bounded and a timeout leaves the repo in a recoverable state” and producing sidecar resource exhaustion plus repo corruption requiring a full wipe?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes a pack whose delta chains and object count explode on the client (deep delta, many tiny objects). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: fetch consumes CPU and memory beyond --sync-timeout, and the timeout kill leaves partial state behind
- Invariant to test: fetch cost is bounded and a timeout leaves the repo in a recoverable state
- Expected Immunefi impact: sidecar resource exhaustion plus repo corruption requiring a full wipe (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
