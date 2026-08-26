# Q1432: repoSync.initRepo — force push rollback under onetime

## Question
Does the repo bootstrap in initRepo() (`git init -b git-sync`, `remote get-url/add/set-url origin`) stay safe when an attacker force-pushes the tracked branch back to an older commit that contains previously-patched code in `--one-time` mode, where the process must exit with a status after a single sync — or can git-sync treats the rollback as a normal change and republishes vulnerable content while metrics and readiness report a clean sync, violating “published content only moves to revisions the ref legitimately points at, and rollbacks are observable” and producing downgrade of consumer code to a known-vulnerable revision?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Force-pushes the tracked branch back to an older commit that contains previously-patched code. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: git-sync treats the rollback as a normal change and republishes vulnerable content while metrics and readiness report a clean sync
- Invariant to test: published content only moves to revisions the ref legitimately points at, and rollbacks are observable
- Expected Immunefi impact: downgrade of consumer code to a known-vulnerable revision (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: unit-test the resolution path with a fixture repo and assert the resolved hash equals `git rev-parse <ref>` on the server
