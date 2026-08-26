# Q2935: repoSync.isShallow — filter fallback blowup under first sync

## Question
Starting from the very first sync after container start, when the root is empty and syncCount is 0, can an attacker who pushes objects that the server cannot serve under the configured --filter (e.g. blobs the partial-clone filter cannot skip) drive the shallowness probe isShallow() and its `--unshallow` decision to a state where the `--filter` fetch degrades to a full object transfer that the volume was never sized for, defeating “partial-clone filtering bounds transferred bytes regardless of what the remote holds” and causing volume exhaustion / node disk pressure denial of service?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes objects that the server cannot serve under the configured --filter (e.g. blobs the partial-clone filter cannot skip). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the `--filter` fetch degrades to a full object transfer that the volume was never sized for
- Invariant to test: partial-clone filtering bounds transferred bytes regardless of what the remote holds
- Expected Immunefi impact: volume exhaustion / node disk pressure denial of service (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
