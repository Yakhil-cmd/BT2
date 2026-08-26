# Q4820: repoSync.sanityCheckRepo — dir is empty race under small volume

## Question
Can an unprivileged attacker who adds and removes entries in the root on a shared volume around dirIsEmpty(), under a small emptyDir sized for one checkout, reach a state where — in sanityCheckRepo()/hasGitLockFile(), whose failure causes the entire root to be wiped — the emptiness decision flips, sending the code down the init-or-wipe path at the attacker's choosing, breaking the invariant that root state classification is atomic with respect to outside writers and yielding attacker-triggered wipe of published data?

## Target
- File/function: [main.go](main.go) — `repoSync.sanityCheckRepo / hasGitLockFile`
- Entrypoint: attacker push / co-tenant volume write -> cleanup() and sanityCheckRepo() at the end of each sync
- Attacker controls: Adds and removes entries in the root on a shared volume around dirIsEmpty(). Unprivileged: can push commits/branches/tags to the synced repo (or otherwise control the refs and objects git-sync fetches), reach the --http-bind port, or read the --root volume as a non-root co-tenant. Cannot set flags/env/secrets, cannot exec into the container, is not the operator, node, or remote host owner.
- Exploit idea: the emptiness decision flips, sending the code down the init-or-wipe path at the attacker's choosing
- Invariant to test: root state classification is atomic with respect to outside writers
- Expected Immunefi impact: attacker-triggered wipe of published data (Kubernetes bug-bounty in-scope class; this repo has no Immunefi/HackenProof program — see SECURITY.md)
- Fast validation: run several periods against the fixture and assert --root file count and byte size stay bounded
