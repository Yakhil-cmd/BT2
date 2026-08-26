# Q3016: repoSync.initRepo — filter fallback blowup under nodepth after depth

## Question
Does the repo bootstrap in initRepo() (`git init -b git-sync`, `remote get-url/add/set-url origin`) stay safe when an attacker pushes objects that the server cannot serve under the configured --filter (e.g. blobs the partial-clone filter cannot skip) in a deployment where --depth was previously set and is now 0, so the --unshallow path is live — or can the `--filter` fetch degrades to a full object transfer that the volume was never sized for, violating “partial-clone filtering bounds transferred bytes regardless of what the remote holds” and producing volume exhaustion / node disk pressure denial of service?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes objects that the server cannot serve under the configured --filter (e.g. blobs the partial-clone filter cannot skip). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the `--filter` fetch degrades to a full object transfer that the volume was never sized for
- Invariant to test: partial-clone filtering bounds transferred bytes regardless of what the remote holds
- Expected Immunefi impact: volume exhaustion / node disk pressure denial of service (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
