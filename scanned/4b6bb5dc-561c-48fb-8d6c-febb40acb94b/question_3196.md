# Q3196: repoSync.initRepo — filter fallback blowup under filter blob none

## Question
Starting from a deployment using `--filter=blob:none` partial clone, can an attacker who pushes objects that the server cannot serve under the configured --filter (e.g. blobs the partial-clone filter cannot skip) drive the repo bootstrap in initRepo() (`git init -b git-sync`, `remote get-url/add/set-url origin`) to a state where the `--filter` fetch degrades to a full object transfer that the volume was never sized for, defeating “partial-clone filtering bounds transferred bytes regardless of what the remote holds” and causing volume exhaustion / node disk pressure denial of service?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes objects that the server cannot serve under the configured --filter (e.g. blobs the partial-clone filter cannot skip). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the `--filter` fetch degrades to a full object transfer that the volume was never sized for
- Invariant to test: partial-clone filtering bounds transferred bytes regardless of what the remote holds
- Expected Immunefi impact: volume exhaustion / node disk pressure denial of service (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
