# Q1396: repoSync.initRepo — force push rollback under nodepth after depth

## Question
Under a deployment where --depth was previously set and is now 0, so the --unshallow path is live, an attacker force-pushes the tracked branch back to an older commit that contains previously-patched code. In the repo bootstrap in initRepo() (`git init -b git-sync`, `remote get-url/add/set-url origin`), can that mean git-sync treats the rollback as a normal change and republishes vulnerable content while metrics and readiness report a clean sync, so that the invariant “published content only moves to revisions the ref legitimately points at, and rollbacks are observable” no longer holds and the outcome is downgrade of consumer code to a known-vulnerable revision?

## Target
- File/function: [main.go](main.go) — `repoSync.initRepo`
- Entrypoint: attacker push to the synced repo -> next `git fetch` in the periodic sync loop
- Attacker controls: Force-pushes the tracked branch back to an older commit that contains previously-patched code. Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: git-sync treats the rollback as a normal change and republishes vulnerable content while metrics and readiness report a clean sync
- Invariant to test: published content only moves to revisions the ref legitimately points at, and rollbacks are observable
- Expected Immunefi impact: downgrade of consumer code to a known-vulnerable revision (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: stand up a local bare repo (file:// or `git daemon`), reproduce the ref/object shape, run git-sync for two periods and diff `readlink <link>` against the ref's real tip
