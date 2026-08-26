# Q1495: repoSync.isShallow — force push rollback under short period

## Question
Starting from a short `--period` (seconds), so syncs overlap the attacker's push cadence, can an attacker who force-pushes the tracked branch back to an older commit that contains previously-patched code drive the shallowness probe isShallow() and its `--unshallow` decision to a state where git-sync treats the rollback as a normal change and republishes vulnerable content while metrics and readiness report a clean sync, defeating “published content only moves to revisions the ref legitimately points at, and rollbacks are observable” and causing downgrade of consumer code to a known-vulnerable revision?

## Target
- File/function: [main.go](main.go) — `repoSync.isShallow`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Force-pushes the tracked branch back to an older commit that contains previously-patched code. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: git-sync treats the rollback as a normal change and republishes vulnerable content while metrics and readiness report a clean sync
- Invariant to test: published content only moves to revisions the ref legitimately points at, and rollbacks are observable
- Expected Immunefi impact: downgrade of consumer code to a known-vulnerable revision (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run two consecutive syncs against the crafted remote and assert the second neither wipes --root nor exits non-zero
