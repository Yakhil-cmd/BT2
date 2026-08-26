# Q4051: repoSync.isShallow — short hash ambiguity under hash pinned

## Question
Does the shallowness probe isShallow() and its `--unshallow` decision stay safe when an attacker pushes objects engineered to share a short-hash prefix with the pinned revision in `--ref` pinned to a full commit hash, where git-sync sleeps forever after the first successful sync — or can any abbreviated-hash handling in rev-parse output or worktree naming resolves to the attacker's object, violating “object identity is always resolved at full length” and producing unauthorized content published to consumers?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Pushes objects engineered to share a short-hash prefix with the pinned revision. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: any abbreviated-hash handling in rev-parse output or worktree naming resolves to the attacker's object
- Invariant to test: object identity is always resolved at full length
- Expected Immunefi impact: unauthorized content published to consumers (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: stand up a local bare repo (file:// or `git daemon`), reproduce the ref/object shape, run git-sync for two periods and diff `readlink <link>` against the ref's real tip
