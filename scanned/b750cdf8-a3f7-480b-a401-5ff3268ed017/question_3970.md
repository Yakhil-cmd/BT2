# Q3970: repoSync.SyncRepo — short hash ambiguity under nodepth after depth

## Question
Starting from a deployment where --depth was previously set and is now 0, so the --unshallow path is live, can an attacker who pushes objects engineered to share a short-hash prefix with the pinned revision drive the hash resolution and change-detection logic in SyncRepo() (`rev-parse FETCH_HEAD^{}`, currentHash vs remoteHash, `reset --soft`) to a state where any abbreviated-hash handling in rev-parse output or worktree naming resolves to the attacker's object, defeating “object identity is always resolved at full length” and causing unauthorized content published to consumers?

## Target
- File/function: [main.go](main.go) — `repoSync.SyncRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes objects engineered to share a short-hash prefix with the pinned revision. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: any abbreviated-hash handling in rev-parse output or worktree naming resolves to the attacker's object
- Invariant to test: object identity is always resolved at full length
- Expected Immunefi impact: unauthorized content published to consumers (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: stand up a local bare repo (file:// or `git daemon`), reproduce the ref/object shape, run git-sync for two periods and diff `readlink <link>` against the ref's real tip
