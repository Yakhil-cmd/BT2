# Q3115: repoSync.isShallow — filter fallback blowup under short period

## Question
Can an unprivileged attacker who pushes objects that the server cannot serve under the configured --filter (e.g. blobs the partial-clone filter cannot skip), under a short `--period` (seconds), so syncs overlap the attacker's push cadence, reach a state where — in the shallowness probe isShallow() and its `--unshallow` decision — the `--filter` fetch degrades to a full object transfer that the volume was never sized for, breaking the invariant that partial-clone filtering bounds transferred bytes regardless of what the remote holds and yielding volume exhaustion / node disk pressure denial of service?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes objects that the server cannot serve under the configured --filter (e.g. blobs the partial-clone filter cannot skip). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the `--filter` fetch degrades to a full object transfer that the volume was never sized for
- Invariant to test: partial-clone filtering bounds transferred bytes regardless of what the remote holds
- Expected Immunefi impact: volume exhaustion / node disk pressure denial of service (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
