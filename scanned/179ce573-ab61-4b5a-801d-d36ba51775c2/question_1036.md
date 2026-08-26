# Q1036: repoSync.initRepo — multi line fetch head under depth1

## Question
Starting from a deployment using `--depth=1` (the documented shallow default for large repos), can an attacker who arranges the remote advertisement so FETCH_HEAD gains multiple entries (extra tags auto-followed alongside the requested ref) drive the repo bootstrap in initRepo() (`git init -b git-sync`, `remote get-url/add/set-url origin`) to a state where the single value parsed out of `rev-parse FETCH_HEAD^{}` is not the ref the operator asked for, defeating “FETCH_HEAD resolution is single-valued and corresponds to the requested ref” and causing unauthorized content published to consumers?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Arranges the remote advertisement so FETCH_HEAD gains multiple entries (extra tags auto-followed alongside the requested ref). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the single value parsed out of `rev-parse FETCH_HEAD^{}` is not the ref the operator asked for
- Invariant to test: FETCH_HEAD resolution is single-valued and corresponds to the requested ref
- Expected Immunefi impact: unauthorized content published to consumers (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
