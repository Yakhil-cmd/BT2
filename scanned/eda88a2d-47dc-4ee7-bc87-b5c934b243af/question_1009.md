# Q1009: repoSync.fetch — multi line fetch head under depth1

## Question
Can an unprivileged attacker who arranges the remote advertisement so FETCH_HEAD gains multiple entries (extra tags auto-followed alongside the requested ref), under a deployment using `--depth=1` (the documented shallow default for large repos), reach a state where — in the argv assembled in fetch() (`fetch <repo> <ref> --verbose --no-progress --prune --no-auto-gc` plus --depth/--unshallow/--filter) — the single value parsed out of `rev-parse FETCH_HEAD^{}` is not the ref the operator asked for, breaking the invariant that FETCH_HEAD resolution is single-valued and corresponds to the requested ref and yielding unauthorized content published to consumers?

## Target
- File/function: [main.go](main.go) — `repoSync.fetch`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Arranges the remote advertisement so FETCH_HEAD gains multiple entries (extra tags auto-followed alongside the requested ref). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the single value parsed out of `rev-parse FETCH_HEAD^{}` is not the ref the operator asked for
- Invariant to test: FETCH_HEAD resolution is single-valued and corresponds to the requested ref
- Expected Immunefi impact: unauthorized content published to consumers (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
