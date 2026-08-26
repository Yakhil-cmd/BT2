# Q5482: repoSync.SyncRepo — packfile resource bomb under crash resume

## Question
Under a resume after the previous process died between fetch and publish, leaving partial state in --root, an attacker pushes a pack whose delta chains and object count explode on the client (deep delta, many tiny objects). In the hash resolution and change-detection logic in SyncRepo() (`rev-parse FETCH_HEAD^{}`, currentHash vs remoteHash, `reset --soft`), can that mean fetch consumes CPU and memory beyond --sync-timeout, and the timeout kill leaves partial state behind, so that the invariant “fetch cost is bounded and a timeout leaves the repo in a recoverable state” no longer holds and the outcome is sidecar resource exhaustion plus repo corruption requiring a full wipe?

## Target
- File/function: [main.go](main.go) — `repoSync.SyncRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes a pack whose delta chains and object count explode on the client (deep delta, many tiny objects). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: fetch consumes CPU and memory beyond --sync-timeout, and the timeout kill leaves partial state behind
- Invariant to test: fetch cost is bounded and a timeout leaves the repo in a recoverable state
- Expected Immunefi impact: sidecar resource exhaustion plus repo corruption requiring a full wipe (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
