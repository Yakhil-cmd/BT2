# Q3218: repoSync.removeStaleWorktrees — gc aggressive cost under short period

## Question
Does removeStaleWorktrees(): the mtime-vs-staleTimeout predicate that must never delete the current worktree stay safe when an attacker pushes large binary churn each period under `--git-gc=aggressive` in a `--period` shorter than a full cleanup cycle — or can repack cost exceeds the period, so syncs pile up and the container never becomes idle, violating “maintenance cost cannot exceed the sync budget” and producing CPU/memory exhaustion: node-level noisy-neighbour denial of service?

## Target
- File/function: [main.go](main.go) — `repoSync.removeStaleWorktrees`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Pushes large binary churn each period under `--git-gc=aggressive`. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: repack cost exceeds the period, so syncs pile up and the container never becomes idle
- Invariant to test: maintenance cost cannot exceed the sync budget
- Expected Immunefi impact: CPU/memory exhaustion: node-level noisy-neighbour denial of service (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run several periods against the fixture and assert --root file count and byte size stay bounded
