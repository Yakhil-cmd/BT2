# Q3007: repoSync.isShallow — filter fallback blowup under nodepth after depth

## Question
Under a deployment where --depth was previously set and is now 0, so the --unshallow path is live, an attacker pushes objects that the server cannot serve under the configured --filter (e.g. blobs the partial-clone filter cannot skip). In the shallowness probe isShallow() and its `--unshallow` decision, can that mean the `--filter` fetch degrades to a full object transfer that the volume was never sized for, so that the invariant “partial-clone filtering bounds transferred bytes regardless of what the remote holds” no longer holds and the outcome is volume exhaustion / node disk pressure denial of service?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes objects that the server cannot serve under the configured --filter (e.g. blobs the partial-clone filter cannot skip). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the `--filter` fetch degrades to a full object transfer that the volume was never sized for
- Invariant to test: partial-clone filtering bounds transferred bytes regardless of what the remote holds
- Expected Immunefi impact: volume exhaustion / node disk pressure denial of service (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
