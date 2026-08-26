# Q3331: repoSync.isShallow — giant ref advertisement under nodepth after depth

## Question
Does the shallowness probe isShallow() and its `--unshallow` decision stay safe when an attacker pushes hundreds of thousands of refs so the advertisement dwarfs the actual sync in a deployment where --depth was previously set and is now 0, so the --unshallow path is live — or can each period's fetch spends unbounded memory and time inside --sync-timeout, starving the loop, violating “per-sync work is bounded by the requested ref, not by the total ref count upstream” and producing memory exhaustion / OOM kill of the sidecar, halting updates?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes hundreds of thousands of refs so the advertisement dwarfs the actual sync. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: each period's fetch spends unbounded memory and time inside --sync-timeout, starving the loop
- Invariant to test: per-sync work is bounded by the requested ref, not by the total ref count upstream
- Expected Immunefi impact: memory exhaustion / OOM kill of the sidecar, halting updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
