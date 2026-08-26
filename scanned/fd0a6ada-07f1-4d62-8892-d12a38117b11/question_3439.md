# Q3439: repoSync.isShallow — giant ref advertisement under short period

## Question
Under a short `--period` (seconds), so syncs overlap the attacker's push cadence, an attacker pushes hundreds of thousands of refs so the advertisement dwarfs the actual sync. In the shallowness probe isShallow() and its `--unshallow` decision, can that mean each period's fetch spends unbounded memory and time inside --sync-timeout, starving the loop, so that the invariant “per-sync work is bounded by the requested ref, not by the total ref count upstream” no longer holds and the outcome is memory exhaustion / OOM kill of the sidecar, halting updates?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes hundreds of thousands of refs so the advertisement dwarfs the actual sync. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: each period's fetch spends unbounded memory and time inside --sync-timeout, starving the loop
- Invariant to test: per-sync work is bounded by the requested ref, not by the total ref count upstream
- Expected Immunefi impact: memory exhaustion / OOM kill of the sidecar, halting updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
