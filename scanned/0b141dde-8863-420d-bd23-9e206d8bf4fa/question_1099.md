# Q1099: repoSync.isShallow — multi line fetch head under onetime

## Question
Can an unprivileged attacker who arranges the remote advertisement so FETCH_HEAD gains multiple entries (extra tags auto-followed alongside the requested ref), under `--one-time` mode, where the process must exit with a status after a single sync, reach a state where — in the shallowness probe isShallow() and its `--unshallow` decision — the single value parsed out of `rev-parse FETCH_HEAD^{}` is not the ref the operator asked for, breaking the invariant that FETCH_HEAD resolution is single-valued and corresponds to the requested ref and yielding unauthorized content published to consumers?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Arranges the remote advertisement so FETCH_HEAD gains multiple entries (extra tags auto-followed alongside the requested ref). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the single value parsed out of `rev-parse FETCH_HEAD^{}` is not the ref the operator asked for
- Invariant to test: FETCH_HEAD resolution is single-valued and corresponds to the requested ref
- Expected Immunefi impact: unauthorized content published to consumers (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
