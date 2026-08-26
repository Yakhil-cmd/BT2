# Q3367: repoSync.isShallow — giant ref advertisement under onetime

## Question
Starting from `--one-time` mode, where the process must exit with a status after a single sync, can an attacker who pushes hundreds of thousands of refs so the advertisement dwarfs the actual sync drive the shallowness probe isShallow() and its `--unshallow` decision to a state where each period's fetch spends unbounded memory and time inside --sync-timeout, starving the loop, defeating “per-sync work is bounded by the requested ref, not by the total ref count upstream” and causing memory exhaustion / OOM kill of the sidecar, halting updates?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes hundreds of thousands of refs so the advertisement dwarfs the actual sync. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: each period's fetch spends unbounded memory and time inside --sync-timeout, starving the loop
- Invariant to test: per-sync work is bounded by the requested ref, not by the total ref count upstream
- Expected Immunefi impact: memory exhaustion / OOM kill of the sidecar, halting updates (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: stand up a local bare repo (file:// or `git daemon`), reproduce the ref/object shape, run git-sync for two periods and diff `readlink <link>` against the ref's real tip
